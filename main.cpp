#include <iostream>
#include <fstream>
#include <linux/can.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>
#include <fcntl.h>
#include <sys/time.h>

std::random_device rd;
std::mt19937 gen(rd());

uint32_t random_id(const std::string &id_type) {
    if (id_type == "short") {
        std::uniform_int_distribution<uint32_t> dis(0, 0x7FF);
        return dis(gen);
    } else if (id_type == "long") {
        std::uniform_int_distribution<uint32_t> dis(0, 0x1FFFFFFF);
        return dis(gen) | CAN_EFF_FLAG;
    } else { // mix
        std::uniform_int_distribution<int> dis(0, 1);
        if (dis(gen))
            return random_id("short");
        else
            return random_id("long");
    }
}

uint8_t random_len() {
    std::uniform_int_distribution<uint8_t> dis(1, 8);
    return dis(gen);
}

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

void write_cap_line(std::ofstream &f, const char *iface, const struct can_frame &frame) {
    struct timeval tv{};
    gettimeofday(&tv, nullptr);

    f << "(" << std::setw(10) << std::setfill('0') << tv.tv_sec << "."
      << std::setw(6) << std::setfill('0') << tv.tv_usec << ") "
      << iface << " ";

    if (frame.can_id & CAN_EFF_FLAG)
        f << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (frame.can_id & CAN_EFF_MASK);
    else
        f << std::hex << std::uppercase << std::setw(3) << std::setfill('0') << (frame.can_id & CAN_SFF_MASK);

    f << "#";
    f << std::hex << std::uppercase;
    for (int i = 0; i < frame.can_dlc; ++i)
        f << std::setw(2) << std::setfill('0') << (int) frame.data[i];
    f << std::dec << "\n";
}

void sender(int sock, std::ofstream &log, std::atomic<bool> &running, const std::string &iface, const std::string &id_type, std::atomic<uint32_t> &counter,
            std::atomic<size_t> &stat_sent) {
    while (running) {
        struct can_frame frame{};

        frame.can_id = random_id(id_type);
        frame.can_dlc = random_len();
        frame.data[0] = (counter++) & 0xFF;
        for (int b = 1; b < frame.can_dlc; ++b)
            frame.data[b] = std::uniform_int_distribution<uint8_t>(0, 255)(gen);

        int n = write(sock, &frame, sizeof(frame));
        if (n == sizeof(frame)) {
            write_cap_line(log, iface.c_str(), frame);
            ++stat_sent;
        }
    }
}

void receiver(int sock, std::ofstream &log, std::atomic<bool> &running, const std::string &iface, std::atomic<size_t> &stat_recv, const std::atomic<size_t> &stat_sent) {
    auto last_receive_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::seconds(10);

    while (true) {
        if (!running.load()) {
            if (stat_recv.load() >= stat_sent.load())
                break;

            auto now = std::chrono::steady_clock::now();
            if (now - last_receive_time > timeout) {
                std::cout << "Таймаут на " << iface << ": принято " << stat_recv << " из " << stat_sent << " сообщений.\n";
                break;
            }
        }

        struct can_frame frame{};
        int n = read(sock, &frame, sizeof(frame));
        if (n == sizeof(frame)) {
            write_cap_line(log, iface.c_str(), frame);
            ++stat_recv;

            last_receive_time = std::chrono::steady_clock::now();
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cout << "Usage: " << argv[0]
                  << " <if_ref> <if_test> <id_type:short|long|mix> <sec>\n";
        std::cout << "Пример: ./cppCanFullDuplexTester can0 can1 mix 5\n";
        return 1;
    }

    std::string if_ref = argv[1];
    std::string if_test = argv[2];
    std::string id_type = argv[3];
    int seconds = std::stoi(argv[4]);
    if (!(id_type == "short" || id_type == "long" || id_type == "mix")) {
        std::cerr << "Неверный тип id. Должно быть short, long или mix\n";
        return 1;
    }

    int s_ref = open_can_socket(if_ref);
    int s_test = open_can_socket(if_test);
    if (s_ref < 0 || s_test < 0) return 1;

    int big_buf = 500000;
    setsockopt(s_ref, SOL_SOCKET, SO_SNDBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_ref, SOL_SOCKET, SO_RCVBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_test, SOL_SOCKET, SO_SNDBUF, &big_buf, sizeof(big_buf));
    setsockopt(s_test, SOL_SOCKET, SO_RCVBUF, &big_buf, sizeof(big_buf));

    int flags = fcntl(s_ref, F_GETFL, 0);
    fcntl(s_ref, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(s_test, F_GETFL, 0);
    fcntl(s_test, F_SETFL, flags | O_NONBLOCK);

    std::ofstream ref_send_log("ref_send.cap");
    std::ofstream ref_recv_log("ref_recv.cap");
    std::ofstream test_send_log("test_send.cap");
    std::ofstream test_recv_log("test_recv.cap");

    std::atomic<bool> running{true};
    std::atomic<uint32_t> ref_counter{0}, test_counter{0};
    std::atomic<size_t> stat_ref_sent{0}, stat_ref_recv{0}, stat_test_sent{0}, stat_test_recv{0};

    std::thread t_send_ref(sender, s_ref, std::ref(ref_send_log), std::ref(running), if_ref, id_type, std::ref(ref_counter), std::ref(stat_ref_sent));
    std::thread t_recv_ref(receiver, s_ref, std::ref(ref_recv_log), std::ref(running), if_ref, std::ref(stat_ref_recv), std::ref(stat_test_sent));
    std::thread t_send_test(sender, s_test, std::ref(test_send_log), std::ref(running), if_test, id_type, std::ref(test_counter), std::ref(stat_test_sent));
    std::thread t_recv_test(receiver, s_test, std::ref(test_recv_log), std::ref(running), if_test, std::ref(stat_test_recv), std::ref(stat_ref_sent));

    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    running = false;

    t_send_ref.join();
    t_recv_ref.join();
    t_send_test.join();
    t_recv_test.join();

    close(s_ref);
    close(s_test);
    ref_send_log.close();
    ref_recv_log.close();
    test_send_log.close();
    test_recv_log.close();

    std::cout << "===== Тест завершен =====\n";
    std::cout << "Интерфейс " << if_ref << " отправил: " << stat_ref_sent
              << " (" << (stat_ref_sent / seconds) << " в сек), получил: " << stat_ref_recv
              << " (" << (stat_ref_recv / seconds) << " в сек)\n";
    std::cout << "Интерфейс " << if_test << " отправил: " << stat_test_sent
              << " (" << (stat_test_sent / seconds) << " в сек), получил: " << stat_test_recv
              << " (" << (stat_test_recv / seconds) << " в сек)\n";
    return 0;
}