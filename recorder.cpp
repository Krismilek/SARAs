// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2021 - 2023 The HEDB Project.
 */

#include "stdafx.hpp"
#include <recorder.hpp>
#include <request.hpp>
#include <request_types.h>
#include <assert.h>
#include <rr_utils.hpp>
#include <iostream>
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

int is_exist[1][32];
int left_flag=false;
int right_flag = false;

//判断是否存在公私钥
bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.is_open();
}

// 生成密钥并保存
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

    FILE* sig_file = fopen("sign.txt", "w");
    if (!sig_file) return false;
    fwrite(base64_data, 1, base64_len, sig_file);
    fclose(sig_file);

    BIO_free_all(bio);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return true;
}

void append_signature_to_file(const char* filename, const char* message) {
    const char* private_key_file = "private_key.pem";

    // 生成并保存签名到Base64文件
    if (!sign_and_save_message_base64(message, private_key_file)) {
        FILE* fp;
        fp = fopen("/var/lib/postgresql/14/main/debug.txt","a");
        if(fp==NULL)
            return;
        fprintf(fp,"Failed to sign and save the message.\n");
        fflush(fp);
        fclose(fp);
        printf("Failed to sign and save the message.\n");
        return;
    }

    // 读取签名内容
    FILE* sig_file = fopen("sign.txt", "r");
    if (!sig_file) {
        printf("Failed to open signature file.\n");
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
        printf("Failed to open file to append signature.\n");
        free(signature);
        return;
    }
    fprintf(fp, "%s\n", signature);
    fclose(fp);

    free(signature);
}

int containsString(const std::string& target) {
    std::ifstream file("/var/lib/postgresql/14/main/sum.txt");
    if (!file.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return 0;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    file.close();

    if (content.find(target) != std::string::npos) {
        return 1;
    } else {
        return 0;
    }
}

void Recorder::update_write_fd(std::string filename_prefix)
{
    if (write_fd) {
        close(write_fd);
    }
    file_length = 0;
    file_cursor = 0;
    write_addr = nullptr;
    pid_t pid = getpid();
    if (filename_prefix == "") {
        filename = "record-" + std::to_string(pid) + ".log";
    } else {
        filename = filename_prefix + "-" + std::to_string(pid) + ".log";
    }
    write_fd = open(filename.c_str(), O_RDWR | O_CREAT, 0666);
}

char* Recorder::get_write_buffer(unsigned long length)
{
    assert(write_fd != 0);
    if (file_cursor + length > file_length) {
        // munmap(write_addr, file_length);
        file_length += DATA_LENGTH;
        ftruncate(write_fd, file_length);
        write_addr = (char*)mmap(NULL, file_length, PROT_READ | PROT_WRITE, MAP_SHARED, write_fd, 0);
        madvise(write_addr + file_cursor, DATA_LENGTH, MADV_SEQUENTIAL);
    }

    char* start = write_addr + file_cursor;
    file_cursor += length;
    return start;
}

void Recorder::record(void* req_buffer)
{
    if (!fileExists("public_key.pem")){
        generate_and_save_keys("public_key.pem","private_key.pem");
    }
    /* left~ to be restructured to class member function */
    BaseRequest* req_control = static_cast<BaseRequest*>(req_buffer);
    if (req_control->reqType != CMD_FLOAT_ENC
        && req_control->reqType != CMD_FLOAT_DEC
        && req_control->reqType >= CMD_FLOAT_PLUS
        && req_control->reqType <= CMD_FLOAT_SUM_BULK) {
        if (req_control->reqType == CMD_FLOAT_CMP) {
            EncFloatCmpRequestData* req = (EncFloatCmpRequestData*)req_buffer;
            size_t length = sizeof(int) * 3 + ENC_FLOAT4_LENGTH * 2 + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 6,
                sizeof(int), &req_control->reqType,
                ENC_FLOAT4_LENGTH, &req->left,
                ENC_FLOAT4_LENGTH, &req->right,
                sizeof(int), &req->cmp,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        } else if (req_control->reqType == CMD_FLOAT_SUM_BULK) {
            EncFloatBulkRequestData* req = (EncFloatBulkRequestData*)req_buffer;
            size_t length = sizeof(int) * 3 + ENC_FLOAT4_LENGTH + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 5,
                sizeof(int), &req_control->reqType,
                sizeof(int), &req->bulk_size,
                ENC_FLOAT4_LENGTH, &req->res,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);

            dst = get_write_buffer(req->bulk_size * ENC_FLOAT4_LENGTH);
            for (int i = 0; i < req->bulk_size; i++) {
                memcpy(dst, &req->items[i], ENC_FLOAT4_LENGTH);
                dst += ENC_FLOAT4_LENGTH;
            }
        } else {
            EncFloatCalcRequestData* req = (EncFloatCalcRequestData*)req_buffer;
            size_t length = sizeof(int) * 2 + ENC_FLOAT4_LENGTH * 3 + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 6,
                sizeof(int), &req->op,
                ENC_FLOAT4_LENGTH, &req->left,
                ENC_FLOAT4_LENGTH, &req->right,
                ENC_FLOAT4_LENGTH, &req->res,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        }
    } // end of float   
    else if (req_control->reqType >= CMD_INT_PLUS
        && req_control->reqType <= CMD_INT_SUM_BULK
        && req_control->reqType != CMD_INT_ENC
        && req_control->reqType != CMD_INT_DEC) {
        if (req_control->reqType == CMD_INT_CMP) {
            EncIntCmpRequestData* req = (EncIntCmpRequestData*)req_buffer;
            size_t length = sizeof(int) * 3 + ENC_INT32_LENGTH * 2 + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            if(!containsString("operator:"+std::to_string(req_control->reqType))){
                uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)) * 1000;
                time_t temp = static_cast<time_t>(timestamp/1000);
                std::string message;
                char sign_buffer[20];
                struct tm *dt;
                char buffer[50];
                dt = localtime(&temp);
                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", dt); 
                std::string filename;
                filename = "/var/lib/postgresql/14/main/sum.txt";
                FILE *fp;
                fp = fopen(filename.c_str(), "a"); // 打开文件以写入模式
                if (fp == NULL) {
                    printf("无法打开文件。\n");
                    return;  
                }  
                fprintf(fp, "%s\n", buffer); 
                fflush(fp);
                fprintf(fp,"operator:%d\n",req_control->reqType);
                fflush(fp);

                sprintf(sign_buffer,"%d",req_control->reqType);
                message+=sign_buffer;

                //left
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->left.iv[j]);
                    fflush(fp);
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->left.tag[j]);
                    fflush(fp);
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->left.data[j]);
                    fflush(fp);
                }
                fprintf(fp,"\n");
                fflush(fp);     
                //right            
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->right.iv[j]);
                    fflush(fp);
                    sprintf(sign_buffer,"%d",req->right.iv[j]);
                    message+=sign_buffer;
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->right.tag[j]);
                    fflush(fp);
                    sprintf(sign_buffer,"%d",req->right.tag[j]);
                    message+=sign_buffer;
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->right.data[j]);
                    fflush(fp);
                    sprintf(sign_buffer,"%d",req->right.data[j]);
                    message+=sign_buffer;
                }
                fprintf(fp,"\n");
                fflush(fp); 

                fprintf(fp,"cmp:%d\n",req->cmp);    
                fflush(fp); 
                fprintf(fp,"resp:%d\n",req_control->resp);
                fflush(fp);
                fclose(fp);
                // append_signature_to_file(filename.c_str(),std::to_string(req_control->reqType).c_str());
                append_signature_to_file(filename.c_str(),message.c_str());
            }
            // rrprintf(1, dst, 6,
            //     sizeof(int), &req_control->reqType,
            //     ENC_INT32_LENGTH, &req->left,
            //     ENC_INT32_LENGTH, &req->right,
            //     sizeof(int), &req->cmp,
            //     sizeof(int), &req_control->resp,
            //     sizeof(uint64_t), &timestamp);
        } else if (req_control->reqType == CMD_INT_SUM_BULK) {
            EncIntBulkRequestData* req = (EncIntBulkRequestData*)req_buffer;
            size_t length = sizeof(int) * 3 + ENC_INT32_LENGTH + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            if(!containsString("operator:"+std::to_string(req_control->reqType))){
                uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)) * 1000;
                time_t temp = static_cast<time_t>(timestamp/1000);
                std::string message;
                char sign_buffer[20];
                struct tm *dt;
                char buffer[50];
                dt = localtime(&temp);
                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", dt); 
                std::string filename;
                filename = "/var/lib/postgresql/14/main/sum.txt";
                FILE *fp;
                fp = fopen(filename.c_str(), "a"); // 打开文件以写入模式
                if (fp == NULL) {
                    printf("无法打开文件。\n");
                    return;  
                }  
                fprintf(fp, "%s\n", buffer); 
                fflush(fp);
                fprintf(fp,"operator:%d\n",req_control->reqType);
                fflush(fp); 

                sprintf(sign_buffer,"%d",req_control->reqType);
                message+=sign_buffer;

                fprintf(fp,"bulk_size:%d\n",req->bulk_size);
                fflush(fp); 
                //result           
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->res.iv[j]);
                    fflush(fp);
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->res.tag[j]);
                    fflush(fp);
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->res.data[j]);
                    fflush(fp);
                }
                fprintf(fp,"\n");
                fflush(fp); 
                fprintf(fp,"resp:%d\n",req_control->resp);
                fflush(fp);

                // rrprintf(1, dst, 5,
                //     sizeof(int), &req_control->reqType,
                //     sizeof(int), &req->bulk_size,
                //     ENC_INT32_LENGTH, &req->res,
                //     sizeof(int), &req_control->resp,
                //     sizeof(uint64_t), &timestamp);

                dst = get_write_buffer(req->bulk_size * ENC_INT32_LENGTH);
                for (int i = 0; i < req->bulk_size; i++) {
                    memcpy(dst, &req->items[i], ENC_INT32_LENGTH);
                    dst += ENC_INT32_LENGTH;

                    //items
                    for(int j = 0;j<IV_SIZE;++j){
                        if(i==0){
                            sprintf(sign_buffer,"%d",req->items[i].iv[j]);
                            message+=sign_buffer;
                        }
                        fprintf(fp,"%d ",req->items[i].iv[j]);
                        fflush(fp);
                    }
                    for(int j = 0;j<TAG_SIZE;++j){
                        if(i==0){
                            sprintf(sign_buffer,"%d",req->items[i].tag[j]);
                            message+=sign_buffer;
                        }
                        fprintf(fp,"%d ",req->items[i].tag[j]);
                        fflush(fp);
                    }
                    for(int j = 0;j<INT32_LENGTH;++j){
                        if(i==0){
                            sprintf(sign_buffer,"%d",req->items[i].data[j]);
                            message+=sign_buffer;
                        }
                        fprintf(fp,"%d ",req->items[i].data[j]);
                        fflush(fp);
                    }
                    fprintf(fp,"\n");
                    fflush(fp);
                }
                fclose(fp);
                append_signature_to_file(filename.c_str(),message.c_str());
            }
            
            // fclose(fp);
        } else {
            EncIntCalcRequestData* req = (EncIntCalcRequestData*)req_buffer;
            size_t length = sizeof(int) * 2 + ENC_INT32_LENGTH * 3 + sizeof(uint64_t);
            char* dst = get_write_buffer(length);

            // if(!containsString("operator:"+std::to_string(req_control->reqType))){
            if(1){
                uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)) * 1000;
                time_t temp = static_cast<time_t>(timestamp/1000);
                std::string message;
                char sign_buffer[20];
                struct tm *dt;
                char buffer[50];
                dt = localtime(&temp);
                strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", dt);
                std::string filename;
                filename = "/var/lib/postgresql/14/main/sum.txt";
                FILE *fp;
                fp = fopen(filename.c_str(), "a"); // 打开文件以写入模式
                if (fp == NULL) {
                    printf("无法打开文件。\n");
                    return;  
                }  
                fprintf(fp, "%s\n", buffer); 
                fflush(fp);
                fprintf(fp,"operator:%d\n",req->op);
                fflush(fp); 
                
                sprintf(sign_buffer, "%d", req->op);
                message += sign_buffer;

                //left
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->left.iv[j]);
                    fflush(fp);
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->left.tag[j]);
                    fflush(fp);
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->left.data[j]);
                    fflush(fp);
                }
                fprintf(fp,"\n");
                fflush(fp); 
                //right            
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->right.iv[j]);
                    fflush(fp);
                    sprintf(sign_buffer, "%d", req->right.iv[j]);
                    message += sign_buffer;
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->right.tag[j]);
                    fflush(fp);
                    sprintf(sign_buffer, "%d", req->right.tag[j]);
                    message += sign_buffer;
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->right.data[j]);
                    fflush(fp);
                    sprintf(sign_buffer, "%d", req->right.data[j]);
                    message += sign_buffer;
                }

                fprintf(fp,"\n");
                fflush(fp); 

                //result          
                for(int j = 0;j<IV_SIZE;++j){
                    fprintf(fp,"%d ",req->res.iv[j]);
                    fflush(fp);
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    fprintf(fp,"%d ",req->res.tag[j]);
                    fflush(fp);
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    fprintf(fp,"%d ",req->res.data[j]);
                    fflush(fp);
                }
                fprintf(fp,"\n");
                fflush(fp);

                fprintf(fp,"resp:%d\n",req_control->resp);
                fflush(fp);
                fclose(fp);
                // append_signature_to_file(filename.c_str(),std::to_string(req_control->reqType).c_str());
                // if(req->op!=1)
                    append_signature_to_file(filename.c_str(),message.c_str());
                // else
                //     append_signature_to_file(filename.c_str(),std::to_string(req_control->reqType).c_str());
                    // append_signature_to_file(filename.c_str(),message.c_str());
            }
            // rrprintf(1, dst, 6,
            //     sizeof(int), &req->op,
            //     ENC_INT32_LENGTH, &req->left,
            //     ENC_INT32_LENGTH, &req->right,
            //     ENC_INT32_LENGTH, &req->res,
            //     sizeof(int), &req_control->resp,
            //     sizeof(uint64_t), &timestamp);
        }
    }
     else if (req_control->reqType != CMD_STRING_ENC
        && req_control->reqType != CMD_STRING_DEC
        && req_control->reqType >= CMD_STRING_CMP
        && req_control->reqType <= CMD_STRING_LIKE) {
        if (req_control->reqType == CMD_STRING_CMP || req_control->reqType == CMD_STRING_LIKE) {
            EncStrCmpRequestData* req = (EncStrCmpRequestData*)req_buffer;
            int left_length = encstr_size(req->left);
            int right_length = encstr_size(req->right);
            int length = sizeof(int) * 5 + left_length + right_length + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 8,
                sizeof(int), &req_control->reqType,
                sizeof(int), &left_length,
                sizeof(int), &right_length,
                left_length, &req->left,
                right_length, &req->right,
                sizeof(int), &req->cmp,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        } else if (req_control->reqType == CMD_STRING_SUBSTRING) {
            SubstringRequestData* req = (SubstringRequestData*)req_buffer;
            int str_length = encstr_size(req->str), result_length = encstr_size(req->res);
            size_t length = sizeof(int) * 4 + str_length + result_length + 2 * ENC_INT32_LENGTH + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 9,
                sizeof(int), &req_control->reqType,
                sizeof(int), &str_length,
                sizeof(int), &result_length,
                str_length, &req->str,
                ENC_INT32_LENGTH, &req->start,
                ENC_INT32_LENGTH, &req->length,
                result_length, &req->res,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        } else {
            EncStrCalcRequestData* req = (EncStrCalcRequestData*)req_buffer;
            int left_length = encstr_size(req->left), right_length = encstr_size(req->right), res_length = encstr_size(req->res);
            int length = sizeof(int) * 5 + left_length + right_length + res_length + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 9,
                sizeof(int), &req->op,
                sizeof(int), &left_length,
                sizeof(int), &right_length,
                sizeof(int), &res_length,
                left_length, &req->left,
                right_length, &req->right,
                res_length, &req->res,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        }
    } else if (req_control->reqType >= CMD_TIMESTAMP_CMP
        && req_control->reqType <= CMD_TIMESTAMP_EXTRACT_YEAR
        && req_control->reqType != CMD_TIMESTAMP_DEC
        && req_control->reqType != CMD_TIMESTAMP_ENC) {
        if (req_control->reqType == CMD_TIMESTAMP_CMP) {
            EncTimestampCmpRequestData* req = (EncTimestampCmpRequestData*)req_buffer;
            int length = sizeof(int) * 3 + ENC_TIMESTAMP_LENGTH * 2 + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 6,
                sizeof(int), &req_control->reqType,
                ENC_TIMESTAMP_LENGTH, &req->left,
                ENC_TIMESTAMP_LENGTH, &req->right,
                sizeof(int), &req->cmp,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        } else if (req_control->reqType == CMD_TIMESTAMP_EXTRACT_YEAR) {
            EncTimestampExtractYearRequestData* req = (EncTimestampExtractYearRequestData*)req_buffer;
            size_t length = sizeof(int) * 2 + ENC_TIMESTAMP_LENGTH + ENC_INT32_LENGTH + sizeof(uint64_t);
            char* dst = get_write_buffer(length);
            uint64_t timestamp = get_timestamp();
            rrprintf(1, dst, 5,
                sizeof(int), &req_control->reqType,
                ENC_TIMESTAMP_LENGTH, &req->in,
                ENC_INT32_LENGTH, &req->res,
                sizeof(int), &req_control->resp,
                sizeof(uint64_t), &timestamp);
        }
    }
}
