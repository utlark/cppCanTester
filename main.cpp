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
#include <set>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <fcntl.h>
#include <sys/time.h>

std::random_device rd;
std::mt19937 gen(rd());

uint32_t random_id(const std::string &id_type) { // NOLINT(*-no-recursion)
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
        else return random_id("long");
    }
}

uint8_t random_len() {
    std::uniform_int_distribution<uint8_t> dis(1, 8);
    return dis(gen);
}

struct Key {
    canid_t id;
    uint8_t counter;

    bool operator<(const Key &o) const {
        if (id != o.id)
            return id < o.id;
        return counter < o.counter;
    }
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

void write_cap_line(std::ofstream &f, const char *iface, const struct can_frame &frame) {
    struct timeval tv{};
    gettimeofday(&tv, nullptr);

    // Время в секундах и микросекундах: 10 знаков до точки, 6 после
    f << "(" << std::setw(10) << std::setfill('0') << tv.tv_sec << "."
      << std::setw(6) << std::setfill('0') << tv.tv_usec << ") "
      << iface << " ";

    // CAN ID — 3 символа (стандарт) или 8 (extended), HEX без 0x
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

int main(int argc, char *argv[]) {
    if (argc != 6) {
        std::cout << "Usage: " << argv[0]
                  << " <if_ref> <if_test> <id_type:short|long|mix> <msg_per_sec|max> <sec>\n";
        std::cout << "Пример: ./cppCanTester can0 can1 short 100 5\n";
        std::cout << "        ./cppCanTester can0 can1 mix max 3\n";
        return 1;
    }

    std::string if_ref = argv[1];
    std::string if_test = argv[2];
    std::string id_type = argv[3];
    std::string rate_str = argv[4];
    int seconds = std::stoi(argv[5]);
    int msg_per_sec = 0;
    bool max_mode = false;
    if (rate_str == "max") {
        max_mode = true;
    } else {
        msg_per_sec = std::stoi(rate_str);
        if (msg_per_sec <= 0) {
            std::cerr << "msg_per_sec должен быть > 0 либо 'max'\n";
            return 1;
        }
    }
    if (!(id_type == "short" || id_type == "long" || id_type == "mix")) {
        std::cerr << "Неверный тип id. Должно быть short, long или mix\n";
        return 1;
    }

    int s_send = open_can_socket(if_ref);
    if (s_send < 0)
        return 1;
    int snd_buf = 500000;
    setsockopt(s_send, SOL_SOCKET, SO_SNDBUF, &snd_buf, sizeof(snd_buf));

    int s_recv = open_can_socket(if_test);
    if (s_recv < 0)
        return 1;
    int flags = fcntl(s_recv, F_GETFL, 0);
    fcntl(s_recv, F_SETFL, flags | O_NONBLOCK);
    int rcv_buf = 500000;
    setsockopt(s_recv, SOL_SOCKET, SO_RCVBUF, &rcv_buf, sizeof(rcv_buf));

    std::set<Key> sent_set;
    std::set<Key> recv_set;
    std::mutex recv_mutex;
    std::atomic<bool> sending_done{false};

    std::ofstream sent_cap("sent.cap");
    std::ofstream recv_cap("recv.cap");

    std::atomic<uint32_t> counter{0};

    // Прием в отдельном потоке
    std::thread recv_thread([&]() {
        while (!sending_done.load() || recv_set.size() < sent_set.size()) {
            struct can_frame frame{};
            int n = read(s_recv, &frame, sizeof(frame));
            if (n == sizeof(frame)) {
                Key k{frame.can_id, frame.data[0]};
                {
                    std::lock_guard<std::mutex> lock(recv_mutex);
                    recv_set.insert(k);
                }
                write_cap_line(recv_cap, if_test.c_str(), frame);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });

    // Отправка
    auto start = std::chrono::steady_clock::now();
    auto end = start + std::chrono::seconds(seconds);

    while (std::chrono::steady_clock::now() < end) {
        struct can_frame frame{};
        frame.can_id = random_id(id_type);
        frame.can_dlc = random_len();
        frame.data[0] = (counter++) & 0xFF; // сквозной счетчик
        for (int b = 1; b < frame.can_dlc; ++b)
            frame.data[b] = std::uniform_int_distribution<uint8_t>(0, 255)(gen);

        int n = write(s_send, &frame, sizeof(frame));
        if (n == sizeof(frame)) {
            sent_set.insert({frame.can_id, frame.data[0]});
            write_cap_line(sent_cap, if_ref.c_str(), frame);
        }
        if (!max_mode) {
            std::this_thread::sleep_for(std::chrono::microseconds(1000000 / msg_per_sec));
        }
    }
    sending_done = true;
    close(s_send);

    recv_thread.join();
    close(s_recv);
    sent_cap.close();
    recv_cap.close();

    // Анализ
    size_t sent = sent_set.size();
    size_t received;
    {
        std::lock_guard<std::mutex> lock(recv_mutex);
        received = recv_set.size();
    }
    size_t lost = 0;
    for (const auto &k: sent_set)
        if (recv_set.count(k) == 0) lost++;

    size_t extras = 0;
    for (const auto &k: recv_set)
        if (sent_set.count(k) == 0) extras++;

    std::cout << "===== Тест завершен =====\n";
    std::cout << "Время теста: " << seconds << " сек\n";
    std::cout << "Фактически отправлено: " << sent << "\n";
    std::cout << "Фактически принято: " << received << "\n";
    std::cout << "Потеряно: " << lost << "\n";
    std::cout << "Изменено: " << extras << "\n";

    return 0;
}
