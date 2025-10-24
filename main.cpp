#include <atomic>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/can.h>
#include <net/if.h>
#include <random>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#include "cxxopts.hpp"

struct MessageBox {
    can_frame frame;
    timeval time;
};

struct Config {
    std::string referenceInterface;
    std::string testedInterface;
    std::string idType = "mix";
    std::string duplexMode = "duplex";
    int msgPerSec = -1;
    int seconds = 1;
    std::string saveMode = "no_save";
    std::string seedStr = "random";
    int timeoutSec = 15;
};

Config appConfig{};
std::atomic<bool> shutdownRequested{false};

std::uniform_int_distribution<uint32_t> disShortId(0, 0x7FF);
std::uniform_int_distribution<uint32_t> disLongId(0, 0x1FFFFFFF);
std::uniform_int_distribution<int> disIdType(0, 1);

std::uniform_int_distribution<uint8_t> disCanDlc(1, 8);
std::uniform_int_distribution<uint8_t> disCanData(0, 255);

int OpenCanSocket(const std::string &interfaceName) {
    int socketFd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (socketFd < 0)
        throw std::system_error(errno, std::system_category(), "Failed to create CAN socket device: " + interfaceName);

    struct ifreq interfaceRequest{};
    std::strncpy(interfaceRequest.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    if (ioctl(socketFd, SIOCGIFINDEX, &interfaceRequest) < 0) {
        close(socketFd);
        throw std::system_error(errno, std::system_category(), "Failed to open CAN socket device: " + interfaceName);
    }

    struct sockaddr_can socketAddress{};
    socketAddress.can_family = AF_CAN;
    socketAddress.can_ifindex = interfaceRequest.ifr_ifindex;
    if (bind(socketFd, (struct sockaddr *) &socketAddress, sizeof(socketAddress)) < 0) {
        close(socketFd);
        throw std::system_error(errno, std::system_category(), "Failed to bind CAN socket device: " + interfaceName);
    }

    return socketFd;
}

uint32_t GetRandomId(const std::string &idType, std::mt19937 &rngGenerator) {
    if (idType == "short")
        return disShortId(rngGenerator);
    else if (idType == "long")
        return disLongId(rngGenerator) | CAN_EFF_FLAG;
    else
        return disIdType(rngGenerator) ? disShortId(rngGenerator) : disLongId(rngGenerator) | CAN_EFF_FLAG;
}

void SenderLoop(int socketFd, std::atomic<size_t> &sentCounter, std::vector<MessageBox> &sentMessages, std::mt19937 &rngGenerator) {
    std::chrono::microseconds sendDelay = (appConfig.msgPerSec > 0) ? std::chrono::microseconds(1000000 / appConfig.msgPerSec) : std::chrono::microseconds(0);
    auto nextSendTime = std::chrono::steady_clock::now();
    struct can_frame canFrame{};
    struct timeval timeValue{};
    uint8_t counter = 0;

    canFrame.can_id = GetRandomId(appConfig.idType, rngGenerator);
    canFrame.can_dlc = disCanDlc(rngGenerator);
    canFrame.data[0] = (counter++) & 0xFF;
    for (int i = 1; i < canFrame.can_dlc; ++i)
        canFrame.data[i] = disCanData(rngGenerator);

    while (!shutdownRequested.load()) {
        ssize_t n = write(socketFd, &canFrame, sizeof(canFrame));
        if (n == sizeof(canFrame)) {
            gettimeofday(&timeValue, nullptr);
            sentMessages.push_back({canFrame, timeValue});
            ++sentCounter;

            std::memset(&canFrame, 0, sizeof(canFrame));
            canFrame.can_id = GetRandomId(appConfig.idType, rngGenerator);
            canFrame.can_dlc = disCanDlc(rngGenerator);
            canFrame.data[0] = (counter++) & 0xFF;
            for (int i = 1; i < canFrame.can_dlc; ++i)
                canFrame.data[i] = disCanData(rngGenerator);
        }

        if (appConfig.msgPerSec > 0) {
            nextSendTime += sendDelay;
            std::this_thread::sleep_until(nextSendTime);
        }
    }
}

void ReceiverLoop(int socketFd, std::atomic<size_t> &receivedCounter, std::vector<MessageBox> &receivedMessages, const std::atomic<size_t> &sentCounter) {
    auto lastReceiveTime = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(appConfig.timeoutSec);
    struct timeval timeValue{};

    while (true) {
        if (shutdownRequested.load()) {
            if (receivedCounter.load() >= sentCounter.load())
                break;
            if (std::chrono::steady_clock::now() - lastReceiveTime > timeout)
                break;
        }

        struct can_frame canFrame{};
        ssize_t n = read(socketFd, &canFrame, sizeof(canFrame));
        if (n == sizeof(canFrame)) {
            gettimeofday(&timeValue, nullptr);
            receivedMessages.push_back({canFrame, timeValue});
            lastReceiveTime = std::chrono::steady_clock::now();
            ++receivedCounter;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void CompareMessages(const std::string &senderInterface, const std::string &receiveInterface,
                     const std::vector<MessageBox> &sentMessages, const std::vector<MessageBox> &receivedMessages) {
    bool allMatch = true;
    uint32_t sentMessageId;
    uint32_t receiveMessageId;

    std::cout << "#### " << senderInterface << " -> " << receiveInterface << " ####\n";
    std::cout << "Sent:     " << sentMessages.size() << " (" << std::floor(sentMessages.size() / appConfig.seconds) << "/s)" << "\n";
    std::cout << "Received: " << receivedMessages.size() << " (" << std::floor(receivedMessages.size() / appConfig.seconds) << "/s)" << "\n";

    for (size_t i = 0; i < std::min(sentMessages.size(), receivedMessages.size()); ++i) {
        if (sentMessages[i].frame.can_id & CAN_EFF_FLAG)
            sentMessageId = sentMessages[i].frame.can_id & CAN_EFF_MASK;
        else
            sentMessageId = sentMessages[i].frame.can_id & CAN_SFF_MASK;

        if (receivedMessages[i].frame.can_id & CAN_EFF_FLAG)
            receiveMessageId = receivedMessages[i].frame.can_id & CAN_EFF_MASK;
        else
            receiveMessageId = receivedMessages[i].frame.can_id & CAN_SFF_MASK;

        if (sentMessageId != receiveMessageId || sentMessages[i].frame.can_dlc != receivedMessages[i].frame.can_dlc) {
            allMatch = false;
            break;
        }

        for (int j = 0; j < sentMessages[i].frame.can_dlc; ++j)
            if (sentMessages[i].frame.data[j] != receivedMessages[i].frame.data[j]) {
                allMatch = false;
                break;
            }
    }

    if (sentMessages.size() > receivedMessages.size()) {
        std::cout << "- Lost messages " << (sentMessages.size() - receivedMessages.size()) << "\n";
        allMatch = false;
    } else if (receivedMessages.size() > sentMessages.size()) {
        std::cout << "- Extra messages " << (receivedMessages.size() - sentMessages.size()) << "\n";
        allMatch = false;
    }

    if (allMatch)
        std::cout << "All messages match in content and order.\n";
    else
        std::cout << "The messages don't match in content and/or order.\n";
}

void SaveMessagesToCap(const std::string &interfaceName, const std::string &filename, const std::vector<MessageBox> &messages) {
    std::ofstream saveStream(interfaceName + "_seed_" + appConfig.seedStr + "_" + filename);
    if (!saveStream.is_open())
        throw std::system_error(errno, std::system_category(), "Unable to open the file for saving: " + interfaceName + "_seed_" + appConfig.seedStr + "_" + filename);

    for (const auto &message: messages) {
        saveStream << "(" << std::setw(10) << std::setfill('0') << message.time.tv_sec << "."
                   << std::setw(6) << std::setfill('0') << message.time.tv_usec << ") "
                   << interfaceName << " ";

        if (message.frame.can_id & CAN_EFF_FLAG)
            saveStream << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (message.frame.can_id & CAN_EFF_MASK);
        else
            saveStream << std::hex << std::uppercase << std::setw(3) << std::setfill('0') << (message.frame.can_id & CAN_SFF_MASK);

        saveStream << "#";
        saveStream << std::hex << std::uppercase;
        for (int i = 0; i < message.frame.can_dlc; ++i)
            saveStream << std::setw(2) << std::setfill('0') << (int) message.frame.data[i];
        saveStream << std::dec << "\n";
    }
}

void LoadConfig(int argc, char *argv[]) {
    cxxopts::Options options(argv[0], "CAN interface tester\n");

    options.add_options()
            ("h,help", "Print usage")
            ("if_ref", "Reference interface name", cxxopts::value<std::string>())
            ("if_test", "Tested interface name", cxxopts::value<std::string>())
            ("id_type", "ID type: short|long|mix", cxxopts::value<std::string>()->default_value("mix"))
            ("duplex_mode", "Duplex mode: duplex|full_duplex", cxxopts::value<std::string>()->default_value("duplex"))
            ("msg_per_sec", "Messages per second: int or max", cxxopts::value<std::string>()->default_value("max"))
            ("sec", "Test duration in seconds", cxxopts::value<int>()->default_value("1"))
            ("save_mode", "Save mode: save|no_save", cxxopts::value<std::string>()->default_value("no_save"))
            ("seed", "Seed: int or random", cxxopts::value<std::string>()->default_value("random"))
            ("timeout_sec", "Timeout in seconds", cxxopts::value<int>()->default_value("15"));

    auto parse = options.parse(argc, argv);

    if (parse.count("help")) {
        std::cout << options.help() << std::endl;
        std::cout << "\nExample: " << argv[0] << " --if_ref=can0 --if_test=can2" << std::endl;
        exit(0);
    }

    if (!parse.count("if_ref") || !parse.count("if_test")) {
        std::cerr << "Error: '--if_ref' and '--if_test' are required.\n";
        std::cout << options.help() << std::endl;
        exit(1);
    }

    appConfig.referenceInterface = parse["if_ref"].as<std::string>();
    appConfig.testedInterface = parse["if_test"].as<std::string>();
    appConfig.idType = parse["id_type"].as<std::string>();
    appConfig.duplexMode = parse["duplex_mode"].as<std::string>();
    appConfig.seconds = parse["sec"].as<int>();
    appConfig.saveMode = parse["save_mode"].as<std::string>();
    appConfig.seedStr = parse["seed"].as<std::string>();
    appConfig.timeoutSec = parse["timeout_sec"].as<int>();

    if (!(appConfig.idType == "short" || appConfig.idType == "long" || appConfig.idType == "mix"))
        throw std::invalid_argument("Invalid '--id_type'. It must be 'short', 'long', or 'mix'.\n");

    if (!(appConfig.duplexMode == "duplex" || appConfig.duplexMode == "full_duplex"))
        throw std::invalid_argument("Invalid '--duplex_mode'. It must be 'duplex' or 'full_duplex'.\n");

    std::string msg_per_sec_str = parse["msg_per_sec"].as<std::string>();
    if (msg_per_sec_str == "max")
        appConfig.msgPerSec = -1;
    else
        try {
            appConfig.msgPerSec = std::stoi(msg_per_sec_str);
            if (appConfig.msgPerSec <= 0)
                throw std::invalid_argument("Invalid '--msg_per_sec'. It must be a positive integer or 'max'\n");
        } catch (...) {
            throw std::invalid_argument("Invalid '--msg_per_sec'. It must be a positive integer or 'max'.\n");
        }

    if (!(appConfig.saveMode == "save" || appConfig.saveMode == "no_save"))
        throw std::invalid_argument("Invalid '--save_mode'. It must be 'save' or 'no_save'.\n");

    if (appConfig.seedStr != "random")
        try {
            int seed = std::stoi(appConfig.seedStr);
            if (seed <= 0) {
                throw std::invalid_argument("Invalid '--seed'. It must be a positive integer or 'random'.\n");
            }
        } catch (...) {
            throw std::invalid_argument("Invalid '--seed'. It must be a positive integer or 'random'.\n");
        }
}

int main(int argc, char *argv[]) {
    LoadConfig(argc, argv);

    std::random_device rngDeviceForReference;
    std::random_device rngDeviceForTested;

    std::mt19937 rngGeneratorForReference(rngDeviceForReference());
    std::mt19937 rngGeneratorForTested(rngDeviceForTested());

    if (appConfig.seedStr != "random") {
        int seed = std::stoi(appConfig.seedStr);
        rngGeneratorForReference.seed(seed);
        rngGeneratorForTested.seed(seed + 1);
    }

    int referenceSocket = OpenCanSocket(appConfig.referenceInterface);
    int testedSocket = OpenCanSocket(appConfig.testedInterface);

    int socketBuffer = 500000;
    setsockopt(referenceSocket, SOL_SOCKET, SO_SNDBUF, &socketBuffer, sizeof(socketBuffer));
    setsockopt(referenceSocket, SOL_SOCKET, SO_RCVBUF, &socketBuffer, sizeof(socketBuffer));
    setsockopt(testedSocket, SOL_SOCKET, SO_SNDBUF, &socketBuffer, sizeof(socketBuffer));
    setsockopt(testedSocket, SOL_SOCKET, SO_RCVBUF, &socketBuffer, sizeof(socketBuffer));

    int flags = fcntl(referenceSocket, F_GETFL, 0);
    fcntl(referenceSocket, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(testedSocket, F_GETFL, 0);
    fcntl(testedSocket, F_SETFL, flags | O_NONBLOCK);

    std::thread referenceSentLoop{}, referenceReceivedLoop{}, testedSentLoop{}, testedReceivedLoop{};
    std::atomic<size_t> referenceSentCounter{0}, referenceReceivedCounter{0}, testedSentCounter{0}, testedReceivedCounter{0};
    std::vector<MessageBox> referenceSentMessages{}, referenceReceivedMessages{}, testedSentMessages{}, testedReceivedMessages{};

    if (appConfig.duplexMode == "full_duplex") {
        referenceReceivedLoop = std::thread(ReceiverLoop, referenceSocket, std::ref(referenceReceivedCounter), std::ref(referenceReceivedMessages), std::ref(testedSentCounter));
        testedReceivedLoop = std::thread(ReceiverLoop, testedSocket, std::ref(testedReceivedCounter), std::ref(testedReceivedMessages), std::ref(referenceSentCounter));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        referenceSentLoop = std::thread(SenderLoop, referenceSocket, std::ref(referenceSentCounter), std::ref(referenceSentMessages), std::ref(rngGeneratorForReference));
        testedSentLoop = std::thread(SenderLoop, testedSocket, std::ref(testedSentCounter), std::ref(testedSentMessages), std::ref(rngGeneratorForTested));
    } else {
        testedReceivedLoop = std::thread(ReceiverLoop, testedSocket, std::ref(testedReceivedCounter), std::ref(testedReceivedMessages), std::ref(referenceSentCounter));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        referenceSentLoop = std::thread(SenderLoop, referenceSocket, std::ref(referenceSentCounter), std::ref(referenceSentMessages), std::ref(rngGeneratorForReference));
    }

    std::this_thread::sleep_for(std::chrono::seconds(appConfig.seconds));
    shutdownRequested.store(true);

    if (appConfig.duplexMode == "full_duplex") {
        referenceSentLoop.join();
        testedReceivedLoop.join();

        testedSentLoop.join();
        referenceReceivedLoop.join();
    } else {
        referenceSentLoop.join();
        testedReceivedLoop.join();
    }

    close(referenceSocket);
    close(testedSocket);

    std::cout << "### Test results ###\n\n";

    if (!referenceSentMessages.empty() || !testedReceivedMessages.empty())
        CompareMessages(appConfig.referenceInterface, appConfig.testedInterface, referenceSentMessages, testedReceivedMessages);

    if ((!referenceSentMessages.empty() || !testedReceivedMessages.empty()) && (!testedSentMessages.empty() || !referenceReceivedMessages.empty()))
        std::cout << std::endl;

    if (!testedSentMessages.empty() || !referenceReceivedMessages.empty())
        CompareMessages(appConfig.testedInterface, appConfig.referenceInterface, testedSentMessages, referenceReceivedMessages);

    if (appConfig.saveMode == "save") {
        if (!referenceSentMessages.empty())
            SaveMessagesToCap(appConfig.referenceInterface, "sent.cap", referenceSentMessages);
        if (!referenceReceivedMessages.empty())
            SaveMessagesToCap(appConfig.referenceInterface, "received.cap", referenceReceivedMessages);

        if (!testedSentMessages.empty())
            SaveMessagesToCap(appConfig.testedInterface, "sent.cap", testedSentMessages);
        if (!testedReceivedMessages.empty())
            SaveMessagesToCap(appConfig.testedInterface, "received.cap", testedReceivedMessages);
    }

    return 0;
}
