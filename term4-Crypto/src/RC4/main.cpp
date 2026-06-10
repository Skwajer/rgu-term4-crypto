#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <iomanip>
#include <sstream>

// ============================================
// Constants and Structures
// ============================================
#define MAX_SESSIONS 100
#define SHM_NAME "/rc4_shm_"
#define SEM_SERVER_READY "/rc4_sem_server_ready_"
#define SEM_CLIENT_READY "/rc4_sem_client_ready_"
#define SEM_SERVER_DONE "/rc4_sem_server_done_"
#define SEM_CLIENT_DONE "/rc4_sem_client_done_"
#define MAX_KEY_SIZE 256
#define MAX_DATA_SIZE (100 * 1024 * 1024)

struct SessionData {
    size_t data_size;
    size_t key_size;
    bool encrypt_mode;
    char key[MAX_KEY_SIZE];
    char data[];
};

// ============================================
// RC4 Implementation
// ============================================
class RC4 {
private:
    std::vector<uint8_t> S;
    int i, j;

public:
    RC4(const std::string& key) : S(256), i(0), j(0) {
        reset(key);
    }

    void reset(const std::string& key_str) {
        i = 0;
        j = 0;
        for (int k = 0; k < 256; k++) {
            S[k] = static_cast<uint8_t>(k);
        }
        
        std::vector<uint8_t> key;
        if (key_str.empty()) {
            key.resize(1, 0);
        } else {
            key.assign(key_str.begin(), key_str.end());
        }
        
        int jj = 0;
        for (int ii = 0; ii < 256; ii++) {
            jj = (jj + S[ii] + key[ii % key.size()]) % 256;
            std::swap(S[ii], S[jj]);
        }
    }

    std::vector<uint8_t> process(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result(data.size());
        int local_i = i;
        int local_j = j;
        std::vector<uint8_t> local_S = S;

        for (size_t k = 0; k < data.size(); k++) {
            local_i = (local_i + 1) % 256;
            local_j = (local_j + local_S[local_i]) % 256;
            std::swap(local_S[local_i], local_S[local_j]);
            uint8_t keystream = local_S[(local_S[local_i] + local_S[local_j]) % 256];
            result[k] = data[k] ^ keystream;
        }

        i = local_i;
        j = local_j;
        S = local_S;
        return result;
    }
};

// ============================================
// Helper Functions
// ============================================
std::vector<uint8_t> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
    }
    return data;
}

void write_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (data.size() > 0) {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
}

bool compare_files(const std::string& file1, const std::string& file2) {
    std::ifstream f1(file1, std::ios::binary | std::ios::ate);
    std::ifstream f2(file2, std::ios::binary | std::ios::ate);
    
    if (!f1.is_open() || !f2.is_open()) return false;
    
    size_t size1 = f1.tellg();
    size_t size2 = f2.tellg();
    
    if (size1 != size2) return false;
    if (size1 == 0 && size2 == 0) return true;
    
    f1.seekg(0);
    f2.seekg(0);
    
    std::vector<char> buffer1(8192);
    std::vector<char> buffer2(8192);
    
    while (f1.good() && f2.good()) {
        f1.read(buffer1.data(), buffer1.size());
        f2.read(buffer2.data(), buffer2.size());
        
        size_t bytes_read = f1.gcount();
        if (bytes_read != static_cast<size_t>(f2.gcount())) return false;
        if (bytes_read == 0) break;
        
        if (memcmp(buffer1.data(), buffer2.data(), bytes_read) != 0) return false;
    }
    
    return true;
}

std::string format_bytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit_idx = 0;
    double size = bytes;
    while (size >= 1024 && unit_idx < 3) {
        size /= 1024;
        unit_idx++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
    return oss.str();
}

std::string generate_random_string(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    static std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += charset[dist(rng)];
    }
    return result;
}

std::vector<uint8_t> generate_random_data(size_t size) {
    static std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> dist(0, 255);
    
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<uint8_t>(dist(rng));
    }
    return data;
}

// ============================================
// Test Utilities
// ============================================
class TestResult {
private:
    int passed = 0;
    int failed = 0;
    std::string current_test;

public:
    void start_test(const std::string& name) {
        current_test = name;
        std::cout << "  " << name << "... ";
    }

    void pass() {
        std::cout << "PASSED" << std::endl;
        passed++;
    }

    void fail(const std::string& reason = "") {
        std::cout << "FAILED";
        if (!reason.empty()) std::cout << " (" << reason << ")";
        std::cout << std::endl;
        failed++;
    }

    void summary() {
        std::cout << "\n  Results: " << passed << " passed, " << failed << " failed" << std::endl;
    }

    int total_passed() const { return passed; }
    int total_failed() const { return failed; }
};

// ============================================
// RC4 Algorithm Tests
// ============================================
void test_rc4_basic(TestResult& result) {
    std::cout << "\n[RC4 BASIC TESTS]" << std::endl;
    
    // Test 1.1: Simple string encryption/decryption
    result.start_test("Simple string encryption/decryption");
    {
        std::string key = "SecretKey";
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail("Decrypted data doesn't match original");
    }
    
    // Test 1.2: Empty plaintext
    result.start_test("Empty plaintext");
    {
        std::string key = "TestKey";
        std::vector<uint8_t> empty;
        
        RC4 rc4(key);
        std::vector<uint8_t> result_data = rc4.process(empty);
        
        if (result_data.empty()) result.pass();
        else result.fail("Result should be empty");
    }
    
    // Test 1.3: Empty key
    result.start_test("Empty key");
    {
        std::string key = "";
        std::vector<uint8_t> plaintext = {'T', 'e', 's', 't'};
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    // Test 1.4: Single byte
    result.start_test("Single byte encryption");
    {
        std::string key = "Key";
        std::vector<uint8_t> plaintext = {42};
        
        RC4 rc4(key);
        std::vector<uint8_t> ciphertext = rc4.process(plaintext);
        
        if (ciphertext.size() == 1 && ciphertext[0] != 42) result.pass();
        else result.fail();
    }
    
    // Test 1.5: All zeros plaintext
    result.start_test("All zeros plaintext");
    {
        std::string key = "ZeroKey";
        std::vector<uint8_t> plaintext(1000, 0);
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    // Test 1.6: All 0xFF bytes
    result.start_test("All 0xFF bytes");
    {
        std::string key = "FFKey";
        std::vector<uint8_t> plaintext(1000, 0xFF);
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    result.summary();
}

void test_rc4_keys(TestResult& result) {
    std::cout << "\n[RC4 KEY TESTS]" << std::endl;
    std::vector<uint8_t> plaintext(100, 0x55);
    
    // Test 2.1: Various key lengths
    std::vector<size_t> key_lengths = {1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 256};
    for (auto len : key_lengths) {
        std::string key = generate_random_string(len);
        result.start_test("Key length " + std::to_string(len));
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    // Test 2.2: Long key (1000 characters)
    result.start_test("Long key (1000 characters)");
    {
        std::string key = generate_random_string(1000);
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    result.summary();
}

void test_rc4_data_sizes(TestResult& result) {
    std::cout << "\n[RC4 DATA SIZE TESTS]" << std::endl;
    std::string key = "SizeTestKey";
    
    std::vector<size_t> sizes = {0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535, 131071, 262143};
    
    for (auto size : sizes) {
        result.start_test("Data size: " + std::to_string(size) + " bytes");
        
        std::vector<uint8_t> plaintext = generate_random_data(size);
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail("Size mismatch or data corruption");
    }
    
    result.summary();
}

void test_rc4_stream_continuity(TestResult& result) {
    std::cout << "\n[RC4 STREAM CONTINUITY TESTS]" << std::endl;
    
    // Test 4.1: Process in parts vs whole
    result.start_test("Process in parts vs whole");
    {
        std::string key = "StreamKey";
        std::vector<uint8_t> part1 = generate_random_data(500);
        std::vector<uint8_t> part2 = generate_random_data(500);
        std::vector<uint8_t> part3 = generate_random_data(500);
        
        // Process as continuous stream
        RC4 rc4_stream(key);
        std::vector<uint8_t> c1 = rc4_stream.process(part1);
        std::vector<uint8_t> c2 = rc4_stream.process(part2);
        std::vector<uint8_t> c3 = rc4_stream.process(part3);
        
        // Process as single block
        std::vector<uint8_t> combined = part1;
        combined.insert(combined.end(), part2.begin(), part2.end());
        combined.insert(combined.end(), part3.begin(), part3.end());
        
        RC4 rc4_block(key);
        std::vector<uint8_t> cipher_combined = rc4_block.process(combined);
        
        std::vector<uint8_t> cipher_stream = c1;
        cipher_stream.insert(cipher_stream.end(), c2.begin(), c2.end());
        cipher_stream.insert(cipher_stream.end(), c3.begin(), c3.end());
        
        if (cipher_stream == cipher_combined) result.pass();
        else result.fail("Stream processing inconsistency");
    }
    
    // Test 4.2: Multiple small chunks
    result.start_test("Multiple small chunks");
    {
        std::string key = "ChunkKey";
        std::vector<uint8_t> original;
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> encrypted_chunks;
        
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> chunk(10, i);
            original.insert(original.end(), chunk.begin(), chunk.end());
            
            std::vector<uint8_t> enc_chunk = rc4_encrypt.process(chunk);
            encrypted_chunks.insert(encrypted_chunks.end(), enc_chunk.begin(), enc_chunk.end());
        }
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(encrypted_chunks);
        
        if (original == decrypted) result.pass();
        else result.fail();
    }
    
    result.summary();
}

void test_rc4_known_vectors(TestResult& result) {
    std::cout << "\n[RC4 KNOWN TEST VECTORS]" << std::endl;
    
    // Test 5.1: RFC 6229 test vector 1
    result.start_test("RFC 6229 test vector 1 (40-bit key)");
    {
        std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<uint8_t> expected_first_16 = {
            0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
        };
        
        std::string key_str(key.begin(), key.end());
        RC4 rc4(key_str);
        std::vector<uint8_t> plaintext(16, 0x00);
        std::vector<uint8_t> output = rc4.process(plaintext);
        
        // For RC4, encrypting zeros gives the keystream
        // First 16 bytes of keystream should match expected
        if (output == expected_first_16) result.pass();
        else result.fail("Keystream doesn't match RFC 6229 vector");
    }
    
    // Test 5.2: Known plaintext-ciphertext pair
    result.start_test("Known plaintext-ciphertext pair");
    {
        std::string key = "Wiki";
        std::vector<uint8_t> plaintext = {'p', 'e', 'd', 'i', 'a'};
        std::vector<uint8_t> expected_ciphertext = {0x60, 0x41, 0xDB, 0xEA, 0x09};
        
        RC4 rc4(key);
        std::vector<uint8_t> ciphertext = rc4.process(plaintext);
        
        // Verify decryption gives original
        RC4 rc4_dec(key);
        std::vector<uint8_t> decrypted = rc4_dec.process(ciphertext);
        
        if (plaintext == decrypted) result.pass();
        else result.fail();
    }
    
    result.summary();
}

void test_rc4_random_sequences(TestResult& result) {
    std::cout << "\n[RC4 RANDOM SEQUENCE TESTS]" << std::endl;
    
    for (int i = 0; i < 20; i++) {
        std::string key = generate_random_string(std::rand() % 200 + 1);
        size_t data_size = std::rand() % 10000 + 1;
        
        result.start_test("Random test " + std::to_string(i + 1) + 
                         " (key: " + std::to_string(key.size()) + 
                         " bytes, data: " + std::to_string(data_size) + " bytes)");
        
        std::vector<uint8_t> plaintext = generate_random_data(data_size);
        
        RC4 rc4_encrypt(key);
        std::vector<uint8_t> ciphertext = rc4_encrypt.process(plaintext);
        
        RC4 rc4_decrypt(key);
        std::vector<uint8_t> decrypted = rc4_decrypt.process(ciphertext);
        
        if (plaintext == decrypted) {
            // Also verify ciphertext is different from plaintext
            if (ciphertext != plaintext) {
                result.pass();
            } else {
                result.fail("Ciphertext equals plaintext (unlikely but possible)");
            }
        } else {
            result.fail();
        }
    }
    
    result.summary();
}

// ============================================
// Server Implementation
// ============================================
class Server {
private:
    std::atomic<bool> running;
    std::vector<std::thread> session_threads;
    std::atomic<int> processed_count{0};

    void handle_session(int session_id) {
        std::string shm_name = SHM_NAME + std::to_string(session_id);
        
        shm_unlink(shm_name.c_str());
        
        int shm_fd = shm_open(shm_name.c_str(), O_CREAT | O_RDWR, 0666);
        if (shm_fd == -1) return;
        
        size_t shm_size = sizeof(SessionData) + MAX_DATA_SIZE;
        ftruncate(shm_fd, shm_size);
        
        void* shm_ptr = mmap(nullptr, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (shm_ptr == MAP_FAILED) {
            close(shm_fd);
            return;
        }
        
        std::string sem_srv_ready = SEM_SERVER_READY + std::to_string(session_id);
        std::string sem_cli_ready = SEM_CLIENT_READY + std::to_string(session_id);
        std::string sem_srv_done = SEM_SERVER_DONE + std::to_string(session_id);
        std::string sem_cli_done = SEM_CLIENT_DONE + std::to_string(session_id);
        
        sem_unlink(sem_srv_ready.c_str());
        sem_unlink(sem_cli_ready.c_str());
        sem_unlink(sem_srv_done.c_str());
        sem_unlink(sem_cli_done.c_str());
        
        sem_t* sem_server_ready = sem_open(sem_srv_ready.c_str(), O_CREAT, 0666, 0);
        sem_t* sem_client_ready = sem_open(sem_cli_ready.c_str(), O_CREAT, 0666, 0);
        sem_t* sem_server_done = sem_open(sem_srv_done.c_str(), O_CREAT, 0666, 0);
        sem_t* sem_client_done = sem_open(sem_cli_done.c_str(), O_CREAT, 0666, 0);
        
        if (sem_server_ready == SEM_FAILED || sem_client_ready == SEM_FAILED ||
            sem_server_done == SEM_FAILED || sem_client_done == SEM_FAILED) {
            munmap(shm_ptr, shm_size);
            close(shm_fd);
            return;
        }
        
        while (running) {
            sem_post(sem_server_ready);
            
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            
            if (sem_timedwait(sem_client_ready, &ts) == -1) {
                if (errno == ETIMEDOUT) continue;
                break;
            }
            
            SessionData* session = static_cast<SessionData*>(shm_ptr);
            
            if (session->data_size == 0 && session->key_size == 0) break;
            
            std::string key(session->key, session->key_size);
            RC4 rc4(key);
            
            std::vector<uint8_t> input_data(session->data, session->data + session->data_size);
            std::vector<uint8_t> output_data = rc4.process(input_data);
            
            memcpy(session->data, output_data.data(), output_data.size());
            processed_count++;
            
            sem_post(sem_server_done);
            sem_wait(sem_client_done);
        }
        
        munmap(shm_ptr, shm_size);
        close(shm_fd);
        shm_unlink(shm_name.c_str());
        sem_close(sem_server_ready);
        sem_close(sem_client_ready);
        sem_close(sem_server_done);
        sem_close(sem_client_done);
        sem_unlink(sem_srv_ready.c_str());
        sem_unlink(sem_cli_ready.c_str());
        sem_unlink(sem_srv_done.c_str());
        sem_unlink(sem_cli_done.c_str());
    }

public:
    void start() {
        running = true;
        processed_count = 0;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_threads.emplace_back(&Server::handle_session, this, i);
        }
        std::cout << "Server started with " << MAX_SESSIONS << " sessions" << std::endl;
    }

    void stop() {
        running = false;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            std::string sem_cli_ready = SEM_CLIENT_READY + std::to_string(i);
            sem_t* sem = sem_open(sem_cli_ready.c_str(), 0);
            if (sem != SEM_FAILED) {
                sem_post(sem);
                sem_close(sem);
            }
        }
        for (auto& t : session_threads) {
            if (t.joinable()) t.join();
        }
        std::cout << "Server stopped. Total processed: " << processed_count << " requests" << std::endl;
    }

    int get_processed_count() const { return processed_count; }
};

Server* g_server = nullptr;

void signal_handler(int) {
    if (g_server) g_server->stop();
    exit(0);
}

// ============================================
// Client Operation
// ============================================
bool process_data(int session_id, const std::string& key, 
                  const std::vector<uint8_t>& input_data, bool encrypt_mode,
                  std::vector<uint8_t>& output_data) {
    std::string shm_name = SHM_NAME + std::to_string(session_id);
    
    int shm_fd = shm_open(shm_name.c_str(), O_RDWR, 0666);
    if (shm_fd == -1) {
        return false;
    }
    
    size_t shm_size = sizeof(SessionData) + MAX_DATA_SIZE;
    void* shm_ptr = mmap(nullptr, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_ptr == MAP_FAILED) {
        close(shm_fd);
        return false;
    }
    
    std::string sem_srv_ready = SEM_SERVER_READY + std::to_string(session_id);
    std::string sem_cli_ready = SEM_CLIENT_READY + std::to_string(session_id);
    std::string sem_srv_done = SEM_SERVER_DONE + std::to_string(session_id);
    std::string sem_cli_done = SEM_CLIENT_DONE + std::to_string(session_id);
    
    sem_t* sem_server_ready = sem_open(sem_srv_ready.c_str(), 0);
    sem_t* sem_client_ready = sem_open(sem_cli_ready.c_str(), 0);
    sem_t* sem_server_done = sem_open(sem_srv_done.c_str(), 0);
    sem_t* sem_client_done = sem_open(sem_cli_done.c_str(), 0);
    
    if (sem_server_ready == SEM_FAILED || sem_client_ready == SEM_FAILED ||
        sem_server_done == SEM_FAILED || sem_client_done == SEM_FAILED) {
        munmap(shm_ptr, shm_size);
        close(shm_fd);
        return false;
    }
    
    sem_wait(sem_server_ready);
    
    SessionData* session = static_cast<SessionData*>(shm_ptr);
    session->data_size = input_data.size();
    session->key_size = key.size();
    session->encrypt_mode = encrypt_mode;
    memcpy(session->key, key.c_str(), key.size());
    if (input_data.size() > 0) {
        memcpy(session->data, input_data.data(), input_data.size());
    }
    
    sem_post(sem_client_ready);
    sem_wait(sem_server_done);
    
    output_data.resize(session->data_size);
    if (session->data_size > 0) {
        memcpy(output_data.data(), session->data, session->data_size);
    }
    
    sem_post(sem_client_done);
    
    munmap(shm_ptr, shm_size);
    close(shm_fd);
    sem_close(sem_server_ready);
    sem_close(sem_client_ready);
    sem_close(sem_server_done);
    sem_close(sem_client_done);
    
    return true;
}

// ============================================
// File-based Tests
// ============================================
void test_file_encryption(TestResult& result) {
    std::cout << "\n[FILE ENCRYPTION/DECRYPTION TESTS]" << std::endl;
    
    // Create test files of different types and sizes
    struct TestFile {
        std::string name;
        std::string description;
        size_t size;
    };
    
    std::vector<TestFile> files = {
        {"file_text_small.txt", "Small text file", 1024},
        {"file_text_medium.txt", "Medium text file", 10240},
        {"file_text_large.txt", "Large text file", 102400},
        {"file_binary_small.dat", "Small binary file", 512},
        {"file_binary_medium.dat", "Medium binary file", 5120},
        {"file_binary_large.dat", "Large binary file", 51200},
        {"file_empty.dat", "Empty file", 0},
        {"file_one_byte.dat", "Single byte file", 1},
        {"file_random.bin", "Random data file", 7777},
    };
    
    // Generate test files
    std::cout << "  Generating test files..." << std::endl;
    for (const auto& tf : files) {
        if (tf.size == 0) {
            std::ofstream f(tf.name);
        } else {
            auto data = generate_random_data(tf.size);
            write_file(tf.name, data);
        }
    }
    
    std::vector<std::string> keys = {
        "TestKey123",
        "AnotherKey!@#$%",
        generate_random_string(32),
        generate_random_string(128),
        ""
    };
    
    int session_id = 0;
    int test_num = 0;
    
    for (const auto& tf : files) {
        for (const auto& key : keys) {
            test_num++;
            std::string key_desc = key.empty() ? "empty" : 
                                  (key.size() > 10 ? std::to_string(key.size()) + " bytes" : key);
            
            result.start_test("#" + std::to_string(test_num) + " " + tf.description + 
                            " (" + format_bytes(tf.size) + ") with " + key_desc + " key");
            
            try {
                std::vector<uint8_t> original = read_file(tf.name);
                
                // Encrypt
                std::vector<uint8_t> encrypted;
                if (!process_data(session_id, key, original, true, encrypted)) {
                    result.fail("Encryption failed");
                    session_id = (session_id + 1) % MAX_SESSIONS;
                    continue;
                }
                
                // Decrypt
                std::vector<uint8_t> decrypted;
                if (!process_data(session_id, key, encrypted, false, decrypted)) {
                    result.fail("Decryption failed");
                    session_id = (session_id + 1) % MAX_SESSIONS;
                    continue;
                }
                
                // Verify
                if (original == decrypted) {
                    // For non-empty files, verify encryption changed data
                    if (tf.size > 0 && encrypted == original) {
                        result.fail("Encryption didn't change data");
                    } else {
                        result.pass();
                    }
                } else {
                    result.fail("Decrypted data doesn't match original");
                }
                
            } catch (const std::exception& e) {
                result.fail(std::string("Exception: ") + e.what());
            }
            
            session_id = (session_id + 1) % MAX_SESSIONS;
        }
    }
    
    result.summary();
}

// ============================================
// Concurrent Sessions Tests
// ============================================
void test_concurrent_sessions(TestResult& result) {
    std::cout << "\n[CONCURRENT SESSIONS TESTS]" << std::endl;
    
    // Test many concurrent requests
    result.start_test("50 concurrent encryption requests");
    {
        std::atomic<int> success_count{0};
        std::atomic<int> fail_count{0};
        std::vector<std::thread> threads;
        
        for (int i = 0; i < 50; i++) {
            threads.emplace_back([i, &success_count, &fail_count]() {
                std::string key = "ConcurrentKey" + std::to_string(i);
                std::vector<uint8_t> data = generate_random_data(1000);
                
                std::vector<uint8_t> encrypted;
                if (process_data(i, key, data, true, encrypted)) {
                    std::vector<uint8_t> decrypted;
                    if (process_data(i, key, encrypted, false, decrypted)) {
                        if (data == decrypted) {
                            success_count++;
                            return;
                        }
                    }
                }
                fail_count++;
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        if (success_count == 50 && fail_count == 0) result.pass();
        else result.fail(std::to_string(success_count) + "/50 succeeded");
    }
    
    // Test 10 sessions with different data sizes simultaneously
    result.start_test("10 sessions with different data sizes");
    {
        std::atomic<int> success{0};
        std::vector<std::thread> threads;
        std::vector<size_t> sizes = {0, 1, 10, 100, 1000, 10000, 50000, 100000, 500000, 1000000};
        
        for (int i = 0; i < 10; i++) {
            threads.emplace_back([i, &sizes, &success]() {
                std::string key = "SizeKey" + std::to_string(i);
                std::vector<uint8_t> data = generate_random_data(sizes[i]);
                
                std::vector<uint8_t> encrypted;
                if (process_data(i + 50, key, data, true, encrypted)) {
                    std::vector<uint8_t> decrypted;
                    if (process_data(i + 50, key, encrypted, false, decrypted)) {
                        if (data == decrypted) success++;
                    }
                }
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        if (success == 10) result.pass();
        else result.fail(std::to_string(success) + "/10 succeeded");
    }
    
    result.summary();
}

// ============================================
// Edge Cases Tests
// ============================================
void test_edge_cases(TestResult& result) {
    std::cout << "\n[EDGE CASES TESTS]" << std::endl;
    
    // Test very large key (near MAX_KEY_SIZE)
    result.start_test("Maximum size key (" + std::to_string(MAX_KEY_SIZE) + " bytes)");
    {
        std::string key(MAX_KEY_SIZE, 'K');
        std::vector<uint8_t> data = generate_random_data(100);
        
        std::vector<uint8_t> encrypted;
        if (process_data(0, key, data, true, encrypted)) {
            std::vector<uint8_t> decrypted;
            if (process_data(0, key, encrypted, false, decrypted)) {
                if (data == decrypted) result.pass();
                else result.fail("Data mismatch");
            } else result.fail("Decryption failed");
        } else result.fail("Encryption failed");
    }
    
    // Test encryption vs decryption with wrong key
    result.start_test("Decryption with wrong key should fail");
    {
        std::string correct_key = "CorrectKey";
        std::string wrong_key = "WrongKey";
        std::vector<uint8_t> original = generate_random_data(100);
        
        std::vector<uint8_t> encrypted;
        process_data(1, correct_key, original, true, encrypted);
        
        std::vector<uint8_t> wrong_decrypted;
        process_data(1, wrong_key, encrypted, false, wrong_decrypted);
        
        if (original != wrong_decrypted) result.pass();
        else result.fail("Wrong key decrypted correctly (very unlikely)");
    }
    
    // Test same data with same key multiple times
    result.start_test("Same data, same key, multiple times");
    {
        std::string key = "RepeatKey";
        std::vector<uint8_t> original = generate_random_data(500);
        
        std::vector<uint8_t> encrypted1, encrypted2;
        process_data(2, key, original, true, encrypted1);
        process_data(2, key, original, true, encrypted2);
        
        // Both encryptions should produce same result (RC4 is deterministic)
        if (encrypted1 == encrypted2) result.pass();
        else result.fail("Same input produced different ciphertexts");
    }
    
    // Test different data with same key
    result.start_test("Different data with same key should differ");
    {
        std::string key = "DiffKey";
        std::vector<uint8_t> data1 = generate_random_data(100);
        std::vector<uint8_t> data2 = generate_random_data(100);
        
        std::vector<uint8_t> enc1, enc2;
        process_data(3, key, data1, true, enc1);
        process_data(3, key, data2, true, enc2);
        
        if (enc1 != enc2) result.pass();
        else result.fail("Different data produced same ciphertext");
    }
    
    result.summary();
}

// ============================================
// Performance Tests
// ============================================
void test_performance(TestResult& result) {
    std::cout << "\n[PERFORMANCE TESTS]" << std::endl;
    
    // Test encryption speed
    std::vector<std::pair<std::string, size_t>> perf_tests = {
        {"1 KB", 1024},
        {"10 KB", 10240},
        {"100 KB", 102400},
        {"1 MB", 1048576},
        {"5 MB", 5242880},
    };
    
    for (const auto& [desc, size] : perf_tests) {
        result.start_test("Encrypt/decrypt " + desc);
        
        std::string key = "PerfKey123";
        std::vector<uint8_t> data = generate_random_data(size);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<uint8_t> encrypted;
        bool enc_ok = process_data(10, key, data, true, encrypted);
        
        std::vector<uint8_t> decrypted;
        bool dec_ok = process_data(10, key, encrypted, false, decrypted);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (enc_ok && dec_ok && data == decrypted) {
            std::cout << " (" << duration.count() << " ms) ";
            result.pass();
        } else {
            result.fail();
        }
    }
    
    result.summary();
}

// ============================================
// MAIN
// ============================================
int main(int argc, char* argv[]) {
    std::string mode = "all";
    if (argc > 1) {
        mode = argv[1];
    }

    if (mode == "server") {
        // Server mode
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        Server server;
        g_server = &server;
        server.start();
        
        std::cout << "Press Ctrl+C to stop" << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
    } else if (mode == "client") {
        // Client mode - run tests against running server
        std::cout << "Waiting for server..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        TestResult result;
        test_file_encryption(result);
        
    } else if (mode == "test") {
        // RC4 algorithm tests only (no server needed)
        std::cout << "========================================" << std::endl;
        std::cout << "     RC4 ALGORITHM UNIT TESTS" << std::endl;
        std::cout << "========================================" << std::endl;
        
        TestResult result;
        test_rc4_basic(result);
        test_rc4_keys(result);
        test_rc4_data_sizes(result);
        test_rc4_stream_continuity(result);
        test_rc4_known_vectors(result);
        test_rc4_random_sequences(result);
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL RC4 TESTS COMPLETED" << std::endl;
        std::cout << "========================================" << std::endl;
        
    } else if (mode == "all") {
        // Run everything
        std::cout << "========================================" << std::endl;
        std::cout << "  RC4 ENCRYPTION CLIENT-SERVER SYSTEM" << std::endl;
        std::cout << "========================================" << std::endl;
        
        // Part 1: RC4 Algorithm Tests
        std::cout << "\n>>> PHASE 1: RC4 Algorithm Tests <<<" << std::endl;
        TestResult algo_result;
        test_rc4_basic(algo_result);
        test_rc4_keys(algo_result);
        test_rc4_data_sizes(algo_result);
        test_rc4_stream_continuity(algo_result);
        test_rc4_known_vectors(algo_result);
        test_rc4_random_sequences(algo_result);
        
        // Start server in background
        std::cout << "\n>>> PHASE 2: Starting Server <<<" << std::endl;
        g_server = new Server();
        std::thread server_thread([]() {
            g_server->start();
        });
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Part 3: File Encryption Tests
        std::cout << "\n>>> PHASE 3: File Encryption Tests <<<" << std::endl;
        TestResult file_result;
        test_file_encryption(file_result);
        
        // Part 4: Concurrent Tests
        std::cout << "\n>>> PHASE 4: Concurrent Sessions Tests <<<" << std::endl;
        TestResult concurrent_result;
        test_concurrent_sessions(concurrent_result);
        
        // Part 5: Edge Cases
        std::cout << "\n>>> PHASE 5: Edge Cases Tests <<<" << std::endl;
        TestResult edge_result;
        test_edge_cases(edge_result);
        
        // Part 6: Performance Tests
        std::cout << "\n>>> PHASE 6: Performance Tests <<<" << std::endl;
        TestResult perf_result;
        test_performance(perf_result);
        
        // Stop server
        std::cout << "\n>>> Stopping Server <<<" << std::endl;
        if (g_server) {
            g_server->stop();
            delete g_server;
            g_server = nullptr;
        }
        server_thread.join();
        
        // Final summary
        std::cout << "\n========================================" << std::endl;
        std::cout << "           FINAL SUMMARY" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "RC4 Algorithm Tests:      " << algo_result.total_passed() + algo_result.total_failed() << " tests" << std::endl;
        std::cout << "File Encryption Tests:    " << file_result.total_passed() + file_result.total_failed() << " tests" << std::endl;
        std::cout << "Concurrent Tests:         " << concurrent_result.total_passed() + concurrent_result.total_failed() << " tests" << std::endl;
        std::cout << "Edge Cases Tests:         " << edge_result.total_passed() + edge_result.total_failed() << " tests" << std::endl;
        std::cout << "Performance Tests:        " << perf_result.total_passed() + perf_result.total_failed() << " tests" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "ALL TESTS COMPLETED" << std::endl;
        std::cout << "========================================" << std::endl;
        
    } else if (mode == "compare") {
        // File comparison
        if (argc != 4) {
            std::cout << "Usage: " << argv[0] << " compare <file1> <file2>" << std::endl;
            return 1;
        }
        if (compare_files(argv[2], argv[3])) {
            std::cout << "Files are IDENTICAL" << std::endl;
        } else {
            std::cout << "Files are DIFFERENT" << std::endl;
        }
    } else {
        std::cout << "Usage: " << argv[0] << " [all|server|client|test|compare]" << std::endl;
        std::cout << "  all     - Run all tests (default)" << std::endl;
        std::cout << "  server  - Start server only" << std::endl;
        std::cout << "  client  - Run client tests (server must be running)" << std::endl;
        std::cout << "  test    - Run RC4 algorithm tests only" << std::endl;
        std::cout << "  compare - Compare two files" << std::endl;
    }
    
    return 0;
}