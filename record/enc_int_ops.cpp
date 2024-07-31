// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2021 - 2023 The HEDB Project.
 */

#include "enc_int_ops.h"
#include "plain_int_ops.h"
#include "base64.h"
#include <string>
#include <fstream>
#include <iostream>
using namespace std;

#include <ctime>
#include <vector>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <fstream>
#include <cstdio>
#include <sstream>
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include <gmpxx.h>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <numeric>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>


bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.is_open();
}

bool generate_and_save_keys(const char* pub_filename, const char* priv_filename) {
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pkey_ctx) return false;

    // 生成密钥对
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 512) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        return false;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // 保存私钥
    FILE* priv_file = fopen(priv_filename, "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(priv_file);

    // 保存公钥
    FILE* pub_file = fopen(pub_filename, "w");
    if (!pub_file) {
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PUBKEY(pub_file, pkey);
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    return true;
}


bool sign_and_save_message_base64(const char* message, const char* priv_filename) {
    // 打开并读取私钥文件
    FILE* priv_file = fopen(priv_filename, "r");
    if (!priv_file) return false;

    EVP_PKEY* pkey = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);
    if (!pkey) return false;

    
    // 对消息进行 SHA-256 哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message), strlen(message), hash);

    // 初始化签名相关变量
    unsigned char* sig = nullptr;
    size_t sig_len = 0;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, hash, sizeof(hash)) <= 0 ||
        EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    sig = (unsigned char*)calloc(sig_len, sizeof(unsigned char));
    if (sig == nullptr) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // 使用 Base64 编码签名
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, sig, sig_len);
    BIO_flush(bio);
    // std::cout << "签名长度：" << sig_len*8 << "bit" <<std::endl;
    // std::cout << sig <<std::endl;
    char* base64_data;
    long base64_len = BIO_get_mem_data(bio, &base64_data);

    // 保存 Base64 编码的签名到文件
    FILE* sig_file = fopen("/var/lib/postgresql/14/main/sign.txt", "w");
    if (!sig_file) {
        free(sig);
        BIO_free_all(bio);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    fwrite(base64_data, 1, base64_len, sig_file);
    fclose(sig_file);

    // 清理
    free(sig);
    BIO_free_all(bio);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return true;
}

void append_signature_to_file(const char* filename, const char* message) {
    const char* private_key_file = "/var/lib/postgresql/14/main/private_key.pem";

    // 生成并保存签名到 Base64 文件
    if (!sign_and_save_message_base64(message, private_key_file)) {
        FILE* fp = fopen("/var/lib/postgresql/14/main/debug.txt", "a");
        if (fp) {
            fprintf(fp, "Failed to sign and save the message.\n");
            fflush(fp);
            fclose(fp);
        }
        std::cerr << "Failed to sign and save the message.\n";
        return;
    }

    // 读取签名内容
    FILE* sig_file = fopen("/var/lib/postgresql/14/main/sign.txt", "r");
    if (!sig_file) {
        std::cerr << "Failed to open signature file.\n";
        return;
    }
    fseek(sig_file, 0, SEEK_END);
    long len = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);
    char* signature = (char*)malloc(len + 1);
    if (signature) {
        fread(signature, 1, len, sig_file);
        signature[len] = '\0';
    }
    fclose(sig_file);

    // 追加签名到文件
    FILE* fp = fopen(filename, "a");
    if (!fp) {
        std::cerr << "Failed to open file to append signature.\n";
        free(signature);
        return;
    }
    fprintf(fp, "%s\n", signature);
    fclose(fp);

    free(signature);
}

std::vector<unsigned char> generate_hmac_key() {
    std::vector<unsigned char> key(64);
    if (!RAND_bytes(key.data(), key.size())) {
        std::cout << "Failed to generate random key" << std::endl;
    }
    return key;
}

std::vector<unsigned char> generate_hmac(const std::string& message, const std::vector<unsigned char>& key) {
    unsigned char* hmac = HMAC(EVP_sha512(), key.data(), key.size(),
                               reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), nullptr, nullptr);
    return std::vector<unsigned char>(hmac, hmac + EVP_MD_size(EVP_sha512()));
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Disable newlines in base64 encoding
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Write data to the BIO
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    // Get the encoded data
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    std::string base64_str(buffer_ptr->data, buffer_ptr->length);
    BUF_MEM_free(buffer_ptr);

    return base64_str;
}

std::string to_base64_string(const std::vector<unsigned char>& data) {
    std::string filename = "/var/lib/postgresql/14/main/mac.txt";
    std::string base64_str = base64_encode(data);

    FILE *fp = fopen(filename.c_str(), "a");
    if (!fp) {
        std::cerr << "Failed to open mac file.\n";
        return "False";
    }
    fprintf(fp, "%s\n", base64_str.c_str());
    fflush(fp);
    fclose(fp);

    return base64_str;
}


// #define LOG_MODE

extern ofstream outfile;

static string b64_int(EncInt* in)
{
    char b64_int4[ENC_INT_B64_LENGTH + 1] = { 0 };
    toBase64((const unsigned char*)in, sizeof(EncInt), b64_int4);
    return b64_int4;
}

//No modify
int enc_int32_cmp(EncIntCmpRequestData* req)
{
    int left, right;
    int resp = 0;

    resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
    if (resp != 0)
        return resp;

    resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
    if (resp != 0)
        return resp;
    decrypt_wait((uint8_t*)&left, sizeof(left));
     
    req->cmp = plain_int32_cmp(left, right);

#ifdef LOG_MODE
    {
        if (0 == req->cmp) outfile << "== ";
        else if (-1 == req->cmp) outfile << "< ";
        else if (1 == req->cmp) outfile << "> ";
        outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " True" << endl;
    }
#endif
    return resp;
}

int enc_int32_calc(EncIntCalcRequestData* req)
{
    int left, right;
    int resp = 0;

    resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
    if (resp != 0)
        return resp;

    resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
    if (resp != 0)
        return resp;

    decrypt_wait((uint8_t*)&left, sizeof(left));

    int res = plain_int32_calc(req->common.reqType, left, right);

    resp = encrypt_bytes((uint8_t*)&res, sizeof(res), (uint8_t*)&req->res, sizeof(req->res));

#ifdef LOG_MODE
    {
        switch (req->common.reqType)
        {
        case CMD_INT_PLUS:  outfile << "+ "; break;
        case CMD_INT_MINUS: outfile << "- "; break;
        case CMD_INT_MULT:  outfile << "* "; break;
        case CMD_INT_DIV:   outfile << "/ "; break;
        case CMD_INT_MOD:   outfile << "% "; break;
        case CMD_INT_EXP:   outfile << "^ "; break;
        default: break;
        }
        outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " " << b64_int(&req->res) << endl;
    }
#endif
    return resp;
}


//HMAC
// int enc_int32_cmp(EncIntCmpRequestData* req)
// {
//     std::string message;
//     char sign_buffer[20];

//     sprintf(sign_buffer, "%d", 5);
//     message += sign_buffer;

//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->right.data[j]);
//         message += sign_buffer;
//     }
//     //left         
//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->left.data[j]);
//         message += sign_buffer;
//     }
//     std::vector<unsigned char> hmac = generate_hmac(message,generate_hmac_key());
//     to_base64_string(hmac);

//     int left, right;
//     int resp = 0;

//     resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
//     if (resp != 0)
//         return resp;

//     resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
//     if (resp != 0)
//         return resp;
//     decrypt_wait((uint8_t*)&left, sizeof(left));
     
//     req->cmp = plain_int32_cmp(left, right);

// #ifdef LOG_MODE
//     {
//         if (0 == req->cmp) outfile << "== ";
//         else if (-1 == req->cmp) outfile << "< ";
//         else if (1 == req->cmp) outfile << "> ";
//         outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " True" << endl;
//     }
// #endif
//     return resp;
// }

// int enc_int32_calc(EncIntCalcRequestData* req)
// {
//     std::string message;
//     char sign_buffer[20];
//     sprintf(sign_buffer, "%d", req->op);
//     message += sign_buffer;

//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->right.data[j]);
//         message += sign_buffer;
//     }
//     //left         
//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->left.data[j]);
//         message += sign_buffer;
//     }
//     std::vector<unsigned char> hmac = generate_hmac(message,generate_hmac_key());
//     to_base64_string(hmac);

//     int left, right;
//     int resp = 0;

//     resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
//     if (resp != 0)
//         return resp;

//     resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
//     if (resp != 0)
//         return resp;

//     decrypt_wait((uint8_t*)&left, sizeof(left));

//     int res = plain_int32_calc(req->common.reqType, left, right);

//     resp = encrypt_bytes((uint8_t*)&res, sizeof(res), (uint8_t*)&req->res, sizeof(req->res));

// #ifdef LOG_MODE
//     {
//         switch (req->common.reqType)
//         {
//         case CMD_INT_PLUS:  outfile << "+ "; break;
//         case CMD_INT_MINUS: outfile << "- "; break;
//         case CMD_INT_MULT:  outfile << "* "; break;
//         case CMD_INT_DIV:   outfile << "/ "; break;
//         case CMD_INT_MOD:   outfile << "% "; break;
//         case CMD_INT_EXP:   outfile << "^ "; break;
//         default: break;
//         }
//         outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " " << b64_int(&req->res) << endl;
//     }
// #endif
//     return resp;
// }


//sign
// int enc_int32_cmp(EncIntCmpRequestData* req)
// {
//     // if (!fileExists("/var/lib/postgresql/14/main/public_key.pem")){
//     //     generate_and_save_keys("/var/lib/postgresql/14/main/public_key.pem","/var/lib/postgresql/14/main/private_key.pem");
//     // }
//     std::string message;
//     char sign_buffer[20];
//     std::string filename;
//     filename = "/var/lib/postgresql/14/main/signature.txt";

//     sprintf(sign_buffer, "%d", 5);
//     message += sign_buffer;

//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->right.data[j]);
//         message += sign_buffer;
//     }
//     //left         
//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->left.data[j]);
//         message += sign_buffer;
//     }
    
//     append_signature_to_file(filename.c_str(),message.c_str());

//     int left, right;
//     int resp = 0;

//     resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
//     if (resp != 0)
//         return resp;

//     resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
//     if (resp != 0)
//         return resp;
//     decrypt_wait((uint8_t*)&left, sizeof(left));
     
//     req->cmp = plain_int32_cmp(left, right);

// #ifdef LOG_MODE
//     {
//         if (0 == req->cmp) outfile << "== ";
//         else if (-1 == req->cmp) outfile << "< ";
//         else if (1 == req->cmp) outfile << "> ";
//         outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " True" << endl;
//     }
// #endif
//     return resp;
// }

// int enc_int32_calc(EncIntCalcRequestData* req)
// {
//     // if (!fileExists("/var/lib/postgresql/14/main/public_key.pem")){
//     //     generate_and_save_keys("/var/lib/postgresql/14/main/public_key.pem","/var/lib/postgresql/14/main/private_key.pem");
//     // }
//     std::string message;
//     char sign_buffer[20];
//     std::string filename;
//     filename = "/var/lib/postgresql/14/main/signature.txt";
//     sprintf(sign_buffer, "%d", req->op);
//     message += sign_buffer;
//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->right.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->right.data[j]);
//         message += sign_buffer;
//     }
//     //left         
//     for(int j = 0;j<IV_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.iv[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<TAG_SIZE;++j){
//         sprintf(sign_buffer, "%d", req->left.tag[j]);
//         message += sign_buffer;
//     }
//     for(int j = 0;j<INT32_LENGTH;++j){
//         sprintf(sign_buffer, "%d", req->left.data[j]);
//         message += sign_buffer;
//     }
    
//     append_signature_to_file(filename.c_str(),message.c_str());


//     int left, right;
//     int resp = 0;

//     resp = decrypt_bytes_para((uint8_t*)&req->left, sizeof(req->left), (uint8_t*)&left, sizeof(left));
//     if (resp != 0)
//         return resp;

//     resp = decrypt_bytes((uint8_t*)&req->right, sizeof(req->right), (uint8_t*)&right, sizeof(right));
//     if (resp != 0)
//         return resp;

//     decrypt_wait((uint8_t*)&left, sizeof(left));

//     int res = plain_int32_calc(req->common.reqType, left, right);

//     resp = encrypt_bytes((uint8_t*)&res, sizeof(res), (uint8_t*)&req->res, sizeof(req->res));

// #ifdef LOG_MODE
//     {
//         switch (req->common.reqType)
//         {
//         case CMD_INT_PLUS:  outfile << "+ "; break;
//         case CMD_INT_MINUS: outfile << "- "; break;
//         case CMD_INT_MULT:  outfile << "* "; break;
//         case CMD_INT_DIV:   outfile << "/ "; break;
//         case CMD_INT_MOD:   outfile << "% "; break;
//         case CMD_INT_EXP:   outfile << "^ "; break;
//         default: break;
//         }
//         outfile << b64_int(&req->left) << " " << b64_int(&req->right) << " " << b64_int(&req->res) << endl;
//     }
// #endif
//     return resp;
// }

int enc_int32_bulk(EncIntBulkRequestData* req)
{
    int bulk_size = req->bulk_size;
    EncInt* array = req->items;
    int count = 0, resp = 0;
    int plain_array[BULK_SIZE];

    while (count < bulk_size) {
        resp = decrypt_bytes((uint8_t*)&array[count], sizeof(EncInt), (uint8_t*)&plain_array[count], sizeof(int));
        if (resp != 0)
            return resp;
        count++;
    }

    int res = plain_int32_bulk(req->common.reqType, req->bulk_size, plain_array);

    resp = encrypt_bytes((uint8_t*)&res, sizeof(res), (uint8_t*)&req->res, sizeof(req->res));
#ifdef LOG_MODE

    {
        outfile << "SUM ";
        for (int id = 0; id < req->bulk_size; id++)
            outfile << b64_int(&array[id]) << " ";
        outfile << b64_int(&req->res) << endl;
    }
#endif
    return resp;
}
