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
#include <fstream>
#include <cstdio>
#include <sstream>
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
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>


bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.is_open();
}


// Generate and save the key
bool generate_and_save_keys(const char* pub_filename, const char* priv_filename) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (EVP_PKEY_keygen_init(pctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) return false;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) return false;

    FILE* priv_file = fopen(priv_filename, "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(priv_file);

    FILE* pub_file = fopen(pub_filename, "w");
    if (!pub_file) {
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PUBKEY(pub_file, pkey);
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return true;
}

//Sign
bool sign_and_save_message_base64(const char* message, const char* priv_filename) {
    FILE* priv_file = fopen(priv_filename, "r");
    if (!priv_file) return false;
    EVP_PKEY* pkey = PEM_read_PrivateKey(priv_file, nullptr, nullptr, nullptr);
    fclose(priv_file);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    size_t sig_len;
    EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSign(md_ctx, nullptr, &sig_len, (const unsigned char*)message, strlen(message));
    std::vector<unsigned char> sig(sig_len);
    EVP_DigestSign(md_ctx, sig.data(), &sig_len, (const unsigned char*)message, strlen(message));

    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, sig.data(), sig_len);
    BIO_flush(bio);
    char* base64_data;
    long base64_len = BIO_get_mem_data(bio, &base64_data);

    FILE* sig_file = fopen("/var/lib/postgresql/14/main/sign.txt", "w");
    if (!sig_file) return false;
    fwrite(base64_data, 1, base64_len, sig_file);
    fclose(sig_file);

    BIO_free_all(bio);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return true;
}

void append_signature_to_file(const char* filename, const char* message) {
    const char* private_key_file = "/var/lib/postgresql/14/main/private_key.pem";

    // Generate and save the signature to a Base64 file
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

//Generate hmac key
std::vector<unsigned char> generate_hmac_key() {
    std::vector<unsigned char> key(32);
    if (!RAND_bytes(key.data(), key.size())) {
        std::cout << "Failed to generate random key" << std::endl;
    }
    return key;
}

//Generate hmac
std::vector<unsigned char> generate_hmac(const std::string& message, const std::vector<unsigned char>& key) {
    unsigned char* hmac = HMAC(EVP_sha256(), key.data(), key.size(),
                               reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), nullptr, nullptr);
    return std::vector<unsigned char>(hmac, hmac + EVP_MD_size(EVP_sha256()));
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
//     // generate_hmac(message,generate_hmac_key());
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
//     // generate_hmac(message,generate_hmac_key());
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
//     if (!fileExists("/var/lib/postgresql/14/main/public_key.pem")){
//         generate_and_save_keys("/var/lib/postgresql/14/main/public_key.pem","/var/lib/postgresql/14/main/private_key.pem");
//     }
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
