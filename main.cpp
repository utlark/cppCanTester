#include <iostream>
#include <fstream>
#include <linux/can.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <random>
#include <thread>
#include <atomic>
#include <iomanip>
#include <fcntl.h>
#include <sys/time.h>
#include <map>

std::random_device rd;
std::mt19937 gen(rd());

std::uniform_int_distribution<uint32_t> dis_short_id(0, 0x7FF);
std::uniform_int_distribution<uint32_t> dis_long_id(0, 0x1FFFFFFF);
std::uniform_int_distribution<int> dis_id_type(0, 1);

std::uniform_int_distribution<uint8_t> dis_can_dlc(1, 8);
std::uniform_int_distribution<uint8_t> dis_can_data(0, 255);

struct MessageBox {
    can_frame frame;
    timeval time;
};

int open_can_socket(const std::string &ifname) {
    int s = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (s < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(s);
        return -1;
    }

    struct sockaddr_can addr{};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        close(s);
        return -1;
    }

    return s;
}

uint32_t random_id(const std::string &id_type) {
    if (id_type == "short")
        return dis_short_id(gen);
    else if (id_type == "long")
        return dis_long_id(gen) | CAN_EFF_FLAG;
    else
        return dis_id_type(gen) ? dis_short_id(gen) : dis_long_id(gen) | CAN_EFF_FLAG;
}

void sender(int sock, std::atomic<bool> &running, const std::string &id_type, std::atomic<size_t> &stat_sent, std::vector<MessageBox> &sent_messages, int msg_per_sec) {
    std::chrono::microseconds delay = (msg_per_sec > 0) ? std::chrono::microseconds(1000000 / msg_per_sec) : std::chrono::microseconds(0);
    auto next_send_time = std::chrono::steady_clock::now();
    uint8_t counter = 0;
    struct timeval tv{};

    while (running) {
        struct can_frame frame{};

        frame.can_id = random_id(id_type);
        frame.can_dlc = dis_can_dlc(gen);
        frame.data[0] = (counter++) & 0xFF;
        for (int b = 1; b < frame.can_dlc; ++b)
            frame.data[b] = dis_can_data(gen);

        ssize_t n = write(sock, &frame, sizeof(frame));
        if (n == sizeof(frame)) {
            gettimeofday(&tv, nullptr);
            sent_messages.push_back({frame, tv});
            ++stat_sent;
        }

        if (msg_per_sec > 0) {
            next_send_time += delay;
            std::this_thread::sleep_until(next_send_time);
        }
    }
}

void receiver(int sock, std::atomic<bool> &running, std::atomic<size_t> &stat_recv, const std::atomic<size_t> &stat_sent, std::vector<MessageBox> &received_messages) {
    auto last_receive_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(30);
    struct timeval tv{};

    while (true) {
        if (!running.load()) {
            if (stat_recv.load() >= stat_sent.load())
                break;
            if (std::chrono::steady_clock::now() - last_receive_time > timeout)
                break;
        }

        struct can_frame frame{};
        ssize_t n = read(sock, &frame, sizeof(frame));
        if (n == sizeof(frame)) {
            gettimeofday(&tv, nullptr);
            received_messages.push_back({frame, tv});
            last_receive_time = std::chrono::steady_clock::now();
            ++stat_recv;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void compare_messages(const std::string &if_sent, const std::string &if_rec, const std::vector<MessageBox> &sent, const std::vector<MessageBox> &received,
                      const std::string &diff_mode, int seconds) {
    uint32_t id_sent;
    uint32_t id_recv;
    bool all_match = true;

    std::cout << "#### " << if_sent << " -> " << if_rec << " ####\n";
    std::cout << "Sent:     " << sent.size() << " (" << std::floor(sent.size() / seconds) << "/s)" << "\n";
    std::cout << "Received: " << received.size() << " (" << std::floor(received.size() / seconds) << "/s)" << "\n";

    for (size_t i = 0; i < std::min(sent.size(), received.size()); ++i) {
        if (sent[i].frame.can_id & CAN_EFF_FLAG)
            id_sent = sent[i].frame.can_id & CAN_EFF_MASK;
        else
            id_sent = sent[i].frame.can_id & CAN_SFF_MASK;

        if (received[i].frame.can_id & CAN_EFF_FLAG)
            id_recv = received[i].frame.can_id & CAN_EFF_MASK;
        else
            id_recv = received[i].frame.can_id & CAN_SFF_MASK;

        if (id_sent != id_recv || sent[i].frame.data[0] != received[i].frame.data[0]) {
            all_match = false;
            if (diff_mode == "show") {
                std::cout << "- Mismatch in position " << i << ": sent (ID: " << std::hex << id_sent
                          << ", data[0]: " << std::dec << (int) sent[i].frame.data[0] << "), received (ID: " << std::hex << id_recv
                          << ", data[0]: " << std::dec << (int) received[i].frame.data[0] << ")\n";
            }
        }
    }

    if (sent.size() > received.size()) {
        std::cout << "- Lost messages " << (sent.size() - received.size()) << "\n";
        all_match = false;
    } else if (received.size() > sent.size()) {
        std::cout << "- Extra messages " << (received.size() - sent.size()) << "\n";
        all_match = false;
    }

    if (all_match)
        std::cout << "All messages match in content and order.\n";
}

void save_messages_to_cap(const std::string &ifname, const std::string &filename, const std::vector<MessageBox> &messages) {
    std::ofstream f(ifname + "_" + filename);
    if (!f.is_open())
        return;

    for (const auto &message: messages) {
        f << "(" << std::setw(10) << std::setfill('0') << message.time.tv_sec << "."
          << std::setw(6) << std::setfill('0') << message.time.tv_usec << ") "
          << ifname << " ";

        if (message.frame.can_id & CAN_EFF_FLAG)
            f << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (message.frame.can_id & CAN_EFF_MASK);
        else
            f << std::hex << std::uppercase << std::setw(3) << std::setfill('0') << (message.frame.can_id & CAN_SFF_MASK);

        f << "#";
        f << std::hex << std::uppercase;
        for (int i = 0; i < message.frame.can_dlc; ++i)
            f << std::setw(2) << std::setfill('0') << (int) message.frame.data[i];
        f << std::dec << "\n";
    }
}

std::map<std::string, std::string> parse_args(int argc, char *argv[]) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto pos = arg.find('=');
        if (pos != std::string::npos) {
            std::string key = arg.substr(0, pos);
            std::string value = arg.substr(pos + 1);
            args[key] = value;
        }
    }
    return args;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0]
                  << " if_ref=<interface_name> if_test=<interface_name> [id_type=short|long|mix] [duplex_mode=duplex|full_duplex] [msg_per_sec=int|max] [sec=int] [diff_mode=show|hide] [save_mode=save|no_save]\n";
        std::cout << "\nExample: " << argv[0] << " if_ref=can0 if_test=can2\n";

        std::cout << "\nDefault values for optional arguments:\n"
                  << "  id_type      = mix\n"
                  << "  duplex_mode  = duplex\n"
                  << "  msg_per_sec  = max\n"
                  << "  sec          = 1\n"
                  << "  diff_mode    = hide\n"
                  << "  save_mode    = no_save\n";
        return 1;
    }
    auto args = parse_args(argc, argv);

    if (!args.count("if_ref") || !args.count("if_test")) {
        std::cerr << "Error: 'if_ref' and 'if_test' are required.\n";
        std::cout << "\nExample: " << argv[0] << " can0 can2\n";
        return 1;
    }

    std::string if_ref = args["if_ref"];
    std::string if_test = args["if_test"];

    std::string id_type = args.count("id_type") ? args["id_type"] : "mix";
    std::string duplex_mode = args.count("duplex_mode") ? args["duplex_mode"] : "duplex";
    std::string msg_per_sec_str = args.count("msg_per_sec") ? args["msg_per_sec"] : "max";
    int seconds = args.count("sec") ? std::stoi(args["sec"]) : 1;
    std::string diff_mode = args.count("diff_mode") ? args["diff_mode"] : "hide";
    std::string save_mode = args.count("save_mode") ? args["save_mode"] : "no_save";

    if (!(id_type == "short" || id_type == "long" || id_type == "mix")) {
        std::cerr << "Invalid id_type. It must be 'short', 'long', or 'mix'.\n";
        return 1;
    }

    if (!(duplex_mode == "duplex" || duplex_mode == "full_duplex")) {
        std::cerr << "Invalid duplex_mode. It must be 'duplex' or 'full_duplex'\n";
        return 1;
    }

    int msg_per_sec = 0;
    if (msg_per_sec_str == "max")
        msg_per_sec = -1;
    else
        try {
            msg_per_sec = std::stoi(msg_per_sec_str);
            if (msg_per_sec <= 0) {
                std::cerr << "msg_per_sec must be a positive number or 'max'\n";
                return 1;
            }
        } catch (const std::invalid_argument &) {
            std::cerr << "Invalid msg_per_sec. It must be an integer or 'max'\n";
            return 1;
        }

    if (!(diff_mode == "show" || diff_mode == "hide")) {
        std::cerr << "Invalid diff_mode. It must be 'show', or 'hide'.\n";
        return 1;
    }

    if (!(save_mode == "save" || save_mode == "no_save")) {
        std::cerr << "Invalid save_mode. It must be 'save', or 'no_save'.\n";
        return 1;
    }

    int s_ref = open_can_socket(if_ref);
    int s_test = open_can_socket(if_test);
    if (s_ref < 0 || s_test < 0)
        return 1;

    int big_buf = 500000;
    setsockopt(s_ref, SOL_SOCKET, SO_SNDBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_ref, SOL_SOCKET, SO_RCVBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_test, SOL_SOCKET, SO_SNDBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_test, SOL_SOCKET, SO_RCVBUF, &big_buf, sizeof(big_buf));

    int flags = fcntl(s_ref, F_GETFL, 0);
    fcntl(s_ref, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(s_test, F_GETFL, 0);
    fcntl(s_test, F_SETFL, flags | O_NONBLOCK);

    std::atomic<bool> running{true};
    std::atomic<size_t> stat_ref_sent{0}, stat_ref_recv{0}, stat_test_sent{0}, stat_test_recv{0};
    std::vector<MessageBox> ref_sent_messages, test_received_messages, test_sent_messages, ref_received_messages;

    std::thread t_send_ref, t_recv_test, t_send_test, t_recv_ref;

    if (duplex_mode == "full_duplex") {
        t_recv_ref = std::thread(receiver, s_ref, std::ref(running), std::ref(stat_ref_recv), std::ref(stat_test_sent), std::ref(ref_received_messages));
        t_recv_test = std::thread(receiver, s_test, std::ref(running), std::ref(stat_test_recv), std::ref(stat_ref_sent), std::ref(test_received_messages));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        t_send_ref = std::thread(sender, s_ref, std::ref(running), id_type, std::ref(stat_ref_sent), std::ref(ref_sent_messages), msg_per_sec);
        t_send_test = std::thread(sender, s_test, std::ref(running), id_type, std::ref(stat_test_sent), std::ref(test_sent_messages), msg_per_sec);

    } else {
        t_recv_test = std::thread(receiver, s_test, std::ref(running), std::ref(stat_test_recv), std::ref(stat_ref_sent), std::ref(test_received_messages));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        t_send_ref = std::thread(sender, s_ref, std::ref(running), id_type, std::ref(stat_ref_sent), std::ref(ref_sent_messages), msg_per_sec);
    }

    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    running = false;

    if (duplex_mode == "full_duplex") {
        t_send_ref.join();
        t_recv_test.join();

        t_send_test.join();
        t_recv_ref.join();
    } else {
        t_send_ref.join();
        t_recv_test.join();
    }

    close(s_ref);
    close(s_test);

    std::cout << "### Test results ###\n\n";

    if (!ref_sent_messages.empty() || !test_received_messages.empty())
        compare_messages(if_ref, if_test, ref_sent_messages, test_received_messages, diff_mode, seconds);

    if ((!ref_sent_messages.empty() || !test_received_messages.empty()) && (!test_sent_messages.empty() || !ref_received_messages.empty()))
        std::cout << std::endl;

    if (!test_sent_messages.empty() || !ref_received_messages.empty())
        compare_messages(if_test, if_ref, test_sent_messages, ref_received_messages, diff_mode, seconds);


    if (save_mode == "save") {
        if (!ref_sent_messages.empty())
            save_messages_to_cap(if_ref, "sent.cap", ref_sent_messages);
        if (!ref_received_messages.empty())
            save_messages_to_cap(if_ref, "received.cap", ref_received_messages);

        if (!test_sent_messages.empty())
            save_messages_to_cap(if_test, "sent.cap", test_sent_messages);
        if (!test_received_messages.empty())
            save_messages_to_cap(if_test, "received.cap", test_received_messages);
    }

    return 0;
}