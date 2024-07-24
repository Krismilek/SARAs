#include "base64.h"
#include <enc_int_ops.hpp>
#include <extension.hpp>
#include <fstream>
#include <iostream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <string>
#include <vector>
#include <cstdio>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstring>
#include <rr_utils.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
// #include <crack.hpp>



#define Max_N 20000
int cnt = 0;//用于多次提取操作数和对比q4的值
std::vector<std::string> satisfiedLines;//用于提取内存表数据
const char* public_key_file = "/var/lib/postgresql/14/main/public_key.pem";

//验证签名
bool verify_signature_base64(const char* message, const char* pub_filename, const char* signatureContent) {
    // 打开并读取公钥
    FILE* pub_file = fopen(pub_filename, "r");
    if (!pub_file) return false;
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pub_file, nullptr, nullptr, nullptr);
    fclose(pub_file);
    if (!pubkey) return false;

    long len = strlen(signatureContent);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
    BIO* bio = BIO_new_mem_buf(signatureContent, len);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> buffer(len); 
    int decoded_len = BIO_read(bio, buffer.data(), len);
    if (decoded_len <= 0) {
        BIO_free_all(bio);
        EVP_PKEY_free(pubkey);
        return false;
    }
    buffer.resize(decoded_len);

    // 创建和初始化EVP_MD_CTX，用于验证签名
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pubkey);
    bool result = EVP_DigestVerify(md_ctx, buffer.data(), buffer.size(), reinterpret_cast<const unsigned char*>(message), strlen(message)) == 1;

    // 清理
    BIO_free_all(bio);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pubkey);

    return result;
}

//提取相应的数字签名内容
bool ExtractSignature( int CaseNum,const std::string& operatorValue, std::string& signature) {
    std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
    std::ifstream file(filepath);
    std::string line;
    std::string operatorLine = "operator:" + operatorValue;
    bool foundOperator = false;
    bool foundResp = false;

    if (!file.is_open()) {
        return false;
    }

    while (getline(file, line)) {
        size_t pos = line.find(operatorLine);
        if (!foundOperator) {
             if (pos != std::string::npos) {
                size_t nextCharPos = pos + operatorLine.length();
                if (nextCharPos == line.length() || (line[nextCharPos] != ':' && !isdigit(line[nextCharPos]))) {
                    foundOperator = true;
                }
            }
        } else if (!foundResp) {
            if (line.find("resp:0") != std::string::npos) {
                foundResp = true;
            }
        } else {
            signature = line;
            return true;
        }
    }
    if(signature.empty()){
        return false;
    }else{
        return true;
    }
}

//针对SUM提取数字签名内容
bool ExtractSumSignature(int CaseNum,std::string& signature){
    std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
    std::ifstream file(filepath); 
    std::string line;
    std::string cmp="operator:"+std::to_string(10);
    int size,index = 0;
    while (std::getline(file, line)) {
        if (line.find(cmp) != std::string::npos) {
            std::getline(file, line); 
            std::size_t pos = line.find(':');
            if (pos != std::string::npos) {
                size = std::stoi(line.substr(pos + 1));
            }
            while(index <= size+2){
                std::getline(file, line);
                index++; 
            }
            signature = line;
            break;
        }
    }
    if(signature.empty()){
        return false;
    }else{
        return true;
    }
}

//TODO 将数组中的数据放入Enc_int变量中
void EncDataCopy(int *data, EncInt* EncData){
    for(int j = 0;j<IV_SIZE;++j){
        EncData->iv[j] = data[j];
    }
    for(int j = 0;j<TAG_SIZE;++j){
        EncData->tag[j] = data[j+IV_SIZE];
    }
    for(int j = 0;j<INT32_LENGTH;++j){
        EncData->data[j] = data[j+IV_SIZE+TAG_SIZE];
    }
}

//将两个EncIntcopy
void EncDataCopy2(EncInt* srcEncData, EncInt* dstEncData){
    for(int j = 0;j<IV_SIZE;++j){
        dstEncData->iv[j] = srcEncData->iv[j];
    }
    for(int j = 0;j<TAG_SIZE;++j){
        dstEncData->tag[j] = srcEncData->tag[j];
    }
    for(int j = 0;j<INT32_LENGTH;++j){
        dstEncData->data[j] = srcEncData->data[j];
    }
}

//判断data数组是否在exist_data中已存在
bool isDataInExistData(const int exist_data[2*Max_N][32], const int data[32]) {
    for (int i = 0; i < 2 * Max_N; ++i) {
        if (std::memcmp(exist_data[i], data, 32 * sizeof(int)) == 0) {
            return true; 
        }
    }
    return false; 
}

//获取操作数
bool ExtractData(int CaseNum,int ops,int *data){
    std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
    std::ifstream file(filepath); 
    std::string line;
    std::string cmp="operator:"+std::to_string(ops);
    std::string operations[] = {"PLUS", "MINUS", "MULT", "DIV","CMP","ENC","DEC","EXP","MOD","SUM_BULK"};
    bool find = false;
    if (!file) {
        printf("Error: Unable to open file\n");
        return false;
    }

    while (std::getline(file, line)) {
        if (line.find(cmp) != std::string::npos) {
            std::getline(file, line); 
            std::getline(file, line); 
            if((CaseNum==5 && ops==10)|| (CaseNum==4 && ops==10)){
                std::getline(file, line); 
                std::getline(file, line);
            }
            std::stringstream ss(line);
            for (int i = 0; i < 32; ++i) {
                ss >> data[i];
                if (ss.fail()) {
                    std::cerr << "Error converting to integer at position " << i << std::endl;
                }
            }
            find = true;
            break;
        }
    }
    if(!find){
        printf("Error: cannot find %s data!\n",operations[ops-1].c_str());
    }
    return find;
}

//第六种情况获取所有操作数
bool ExtractData2(int CaseNum,int ops,int exist_data[2*Max_N][32]){
    cnt = 0;
    std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
    std::ifstream file(filepath); 
    std::string line;
    std::string cmp="operator:"+std::to_string(ops);
    std::string operations[] = {"PLUS", "MINUS", "MULT", "DIV","CMP","ENC","DEC","EXP","MOD","SUM_BULK"};
    int data[32];
    bool find=false;

    if (!file) {
        printf("Error: Unable to open file\n");
        return false;
    }

    while (std::getline(file, line)) {
        if (line.find(cmp) != std::string::npos) {
            std::getline(file, line); 
            std::getline(file, line); 
            std::stringstream ss(line);
            for (int i = 0; i < 32; ++i) {
                ss >> data[i];
                if (ss.fail()) {
                    std::cerr << "Error converting to integer at position " << i << std::endl;
                }
            }
            if(!isDataInExistData(exist_data,data)){
                for(int i = 0;i<32;i++){
                    exist_data[cnt][i] = data[i];
                }
                cnt++;
            }
            find = true;
        }
    }
    if(!find){
        printf("Error: cannot find %s data!\n",operations[ops-1].c_str());
    }
    return find;
}

//提取数字签名并验证,其中signControl代表要验证的是单操作符还是绑定操作数，分别用1和2表示
bool ExtractAndVerify(int CaseNum,int ops,int signControl){
    int data[32];
    std::string operations[] = {"PLUS", "MINUS", "MULT", "DIV","CMP","ENC","DEC","EXP","MOD","SUM_BULK"};
    std::string message;
    std::string operatorValue; 
    std::string signature;
    char sign_buffer[20];
    
    if(signControl==2){
        if(!ExtractData(CaseNum,ops,data)) return false;
        sprintf(sign_buffer,"%d",ops);
        message+=sign_buffer;
        for(int i = 0;i<32;i++){
            sprintf(sign_buffer,"%d",data[i]);
            message+=sign_buffer;
        }
    }else{
        message = std::to_string(ops);
    }
    
    if(ops!=10){
        if(ExtractSignature(CaseNum, std::to_string(ops), signature)){
            printf("********%s操作符签名内容提取成功************\n",operations[ops-1].c_str());
            std::cout<<signature<<std::endl;
        } else{
            printf("********%s操作符签名内容提取失败************\n",operations[ops-1].c_str());
            return false;
        }
    }else{
        if(ExtractSumSignature(CaseNum, signature)){
            printf("********%s操作符签名内容提取成功************\n",operations[ops-1].c_str());
            std::cout<<signature<<std::endl;
        } else{
            printf("********%s操作符签名内容提取失败************\n",operations[ops-1].c_str());
            return false;
        }
    }
    

    if(verify_signature_base64(message.c_str(),public_key_file,signature.c_str())){
        printf("%s操作符通过签名!\n",operations[ops-1].c_str());
        return true;
    } else{
        printf("%s操作符无法通过签名!\n",operations[ops-1].c_str());
        return false;
    }
    return true;
}

//信息写入文件
void DataWrite(FILE* file,EncInt* enc_data){
    for(int i = 0;i<IV_SIZE;i++){
        fprintf(file,"%d ",enc_data->iv[i]);
        fflush(file);
    }
    for(int i = 0;i<TAG_SIZE;i++){
        fprintf(file,"%d ",enc_data->tag[i]);
        fflush(file);
    }
    for(int i = 0;i<INT32_LENGTH;i++){
        fprintf(file,"%d ",enc_data->data[i]);
        fflush(file);
    }
    fprintf(file,"\n");
    fflush(file);
}

//获取内存表的数据
bool fromLog_Store(int CaseNum){
    std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
    std::ifstream file(filepath); 
    std::string line;
    bool foundOperator5 = false;
    bool firstBlock = true;
    int row = 1;
    std::vector<std::vector<int>> data;

    while (std::getline(file, line)) {
        if (line.find("operator:5") != std::string::npos) {
            if (firstBlock) { 
                foundOperator5 = true;
            } else {
                break; 
            }
        } else if (foundOperator5) {
            std::vector<int> satisfiedLines;
            int num;
            std::istringstream iss(line);
            while (iss >> num) {
                satisfiedLines.push_back(num); 
            }
            data.push_back(satisfiedLines);
            satisfiedLines.clear();
            if (std::getline(file, line)) {
                std::istringstream iss(line);
                while (iss >> num) {
                    satisfiedLines.push_back(num);
                }
                data.push_back(satisfiedLines);
            }
            std::getline(file, line); // cmp行
            std::getline(file, line); // resp行
            std::getline(file, line); //sign行
            std::getline(file, line); // timestamp行

            std::streampos oldPos = file.tellg();
            if (std::getline(file, line) && line.find("operator:5") == std::string::npos) {
                firstBlock = false; 
                foundOperator5 = false;
            }
            file.seekg(oldPos); 
        }
    }

    if(data.size()==0)
        return false;

    for(int i = 0;i < 32;i++){
        if(data[0][i] != data[2][i]){
            row = 0;
            break;
        }
    }
    FILE* fp;
    fp = fopen("/var/lib/postgresql/14/main/store.txt","a");
    for(;row <data.size();row +=2){
        for(int j = 0;j < 32;j++){
            fprintf(fp,"%d ",data[row][j]);
            fflush(fp);
        }
        fprintf(fp,"\n");
        fflush(fp);
    }
    fclose(fp);
    return true;
}

//使用除法操作符获取'1'
bool get_cipher_one(int CaseNum){
    std::string inputFilePath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt"; 
    std::ifstream inputFile(inputFilePath);
    std::string line;
    std::vector<std::string> buffer;
    std::vector<int> left_data(32);
    bool foundOperator4 = false;
    int data[32];
    EncInt* enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* div_left = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* div_right = (EncInt*)palloc0(sizeof(EncInt)); 

    
    //验证签名
    if(CaseNum == 1){
        if(!ExtractAndVerify(CaseNum,4,1))
            return false;
    }
    else{
        if(!ExtractAndVerify(CaseNum,4,2))
            return false;
    }
    if (inputFile.is_open()) {
        while (getline(inputFile, line)) {
            if (line.find("operator:4") != std::string::npos) {
                foundOperator4 = true;
                buffer.clear(); 
            } else if (foundOperator4) {
                buffer.push_back(line);
                if (buffer.size() >= 2) { 
                    break;
                }
            } 
        }
        inputFile.close();
    } else {
        std::cerr << "Unable to open file" << std::endl;
        return -2;
    }
    std::istringstream iss(buffer[1]);
    int num;
    int index = 0;
    while (iss >> num && index < 32) {
        left_data[index++] = num;
        iss.ignore();
    }   
    for(int i = 0 ;i<32;i++)
        data[i] = left_data[i];
    //将左操作数和右操作数赋值
    EncDataCopy(data,div_left);
    EncDataCopy(data,div_right);
    enc_int_div(div_left, div_right, enc_one);
    std::ofstream("/var/lib/postgresql/14/main/part.txt", std::ofstream::out).close();
    FILE * file;
    file = fopen("/var/lib/postgresql/14/main/part.txt","a");
    if(file==NULL) {
        printf("无法打开文件\n");
        return false;
    }
    //写入对应文件
    DataWrite(file,enc_one);
    fclose(file);
    return true;
}

//加法操作符
bool get_cipher_from_1_to_n(int CaseNum){
    int data[32];
    //验证签名
    if(!ExtractAndVerify(CaseNum,1,1))
        return false;
    
    EncInt* add_left = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* add_res = (EncInt*)palloc0(sizeof(EncInt));
    std::ifstream inputFile("/var/lib/postgresql/14/main/part.txt"); 
    for (int j = 0; j < 32; ++j) {
        inputFile >> data[j];
    }
    inputFile.close();
    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
    if (file == NULL) {
        printf("无法打开文件。\n");
        return false;
    }
    EncDataCopy(data,add_left);
    EncDataCopy(data,add_res);
    //使用加法获得2-n
    for(int i = 1; i <Max_N; i++){
        int error= enc_int_add(add_left, add_res, add_res);
        DataWrite(file,add_res);
    }  
    fclose(file);
    return true;
}

//使用减号获取-1~-n的密文
bool get_cipher_from_n1_nn(int CaseNum){
    int Enc_one_Data[32];
    int sub_data[32];
    EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData_Add_1 = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_N1 = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* add_res = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_zero = (EncInt*)palloc0(sizeof(EncInt));
    std::ifstream inputFile("/var/lib/postgresql/14/main/part.txt"); 
    for (int i = 0; i < 32; ++i) {
        inputFile >> Enc_one_Data[i];
    }
    inputFile.close();
    //'1'的密文
    EncDataCopy(Enc_one_Data,Enc_one);

    //sub操作数的密文
    if(!ExtractData(CaseNum,2,sub_data)) return false;
    EncDataCopy(sub_data,Enc_SubData);
    //获得sub+1
    enc_int_add(Enc_one,Enc_SubData,Enc_SubData_Add_1);
    //验证签名
    if(!ExtractAndVerify(CaseNum,2,2))
        return false;

    //获得-1
    enc_int_sub(Enc_SubData,Enc_SubData_Add_1,Enc_N1);
    //获得0
    enc_int_sub(Enc_SubData,Enc_SubData,Enc_zero);
    enc_int_sub(Enc_SubData,Enc_SubData,add_res);
    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
    if (file == NULL) {
        printf("无法打开文件。\n");
    }
    DataWrite(file,Enc_zero);
    for(int i = 0; i < Max_N; i++){
        int error= enc_int_add(Enc_N1, add_res, add_res);
        for(int j = 0;j<IV_SIZE;j++){
            fprintf(file,"%d ",add_res->iv[j]);
            fflush(file);
        }
        for(int j = 0;j<TAG_SIZE;j++){
            fprintf(file,"%d ",add_res->tag[j]);
            fflush(file);
        }
        for(int j = 0;j<INT32_LENGTH;j++){
            fprintf(file,"%d ",add_res->data[j]);
            fflush(file);
        }
        fprintf(file,"\n");
        fflush(file);
    }  
    fclose(file);
    return true;
}

//在第四、五种情况获取全域密文
bool get_cipher_from_1_to_n_sum(int CaseNum){
    int data[32];
    int bulk_size = 2;
    EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SumData = (EncInt*)palloc0(sizeof(EncInt)); 
    EncInt* Enc_zero = (EncInt*)palloc0(sizeof(EncInt)); //0
    EncInt* Enc_N1 = (EncInt*)palloc0(sizeof(EncInt)); //-1
    EncInt* Enc_temp = (EncInt*)palloc0(sizeof(EncInt)); //q2-q3
    EncInt* Enc_SubData_N1 = (EncInt*)palloc0(sizeof(EncInt)); //q2-1
    EncInt* sum = (EncInt*)palloc0(sizeof(EncInt)); //sum
    EncInt* Enc_cipher = (EncInt*)palloc0(sizeof(EncInt)); //store 2-n ciper
    EncInt sum_array[256];
    std::ifstream inputFile("/var/lib/postgresql/14/main/part.txt"); 
    for (int i = 0; i < 32; ++i) {
        inputFile >> data[i];
    }
    inputFile.close();

    //'1'的密文
    EncDataCopy(data,Enc_one);
    //获取减法操作数和验证减法操作
    if(!ExtractData(5,2,data)) return false;
    EncDataCopy(data,Enc_SubData);
    if(!ExtractAndVerify(CaseNum,2,2)) //验证签名
        return false;

    //获取sum操作数
    if(!ExtractData(5,10,data)) return false;
    EncDataCopy(data,Enc_SumData);
    if(!ExtractAndVerify(CaseNum,10,2)) //验证签名
        return false;

    enc_int_sub(Enc_SubData,Enc_SubData,Enc_zero); //0
    enc_int_sub(Enc_SubData,Enc_SumData,Enc_temp); //q2-q3
    enc_int_sub(Enc_SubData,Enc_one,Enc_SubData_N1); //q2-1
    enc_int_sub(Enc_SubData_N1,Enc_SubData,Enc_N1); //-1

    EncDataCopy2(Enc_SumData,&sum_array[0]);   
    EncDataCopy2(Enc_temp,&sum_array[1]); 
    EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);  
    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
    if (file == NULL) {
        printf("无法打开文件。\n");
    } 
    FILE *fp;
    fp = fopen("/var/lib/postgresql/14/main/NN.txt", "a");
    if (fp == NULL) {
        printf("无法打开文件。\n");
    } 
    //0
    DataWrite(fp,Enc_zero);
    //-1
    DataWrite(fp,Enc_N1);
    //获取2~n,-2~-n
    for(int i=2;i<=Max_N;i++){
        EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);
        enc_int_sum_bulk(bulk_size,sum_array,sum);
        if(bulk_size==256){
            EncDataCopy2(sum,&sum_array[0]);
            bulk_size=1;
        }        
        enc_int_sub(Enc_SubData,sum,Enc_cipher);
        DataWrite(file,Enc_cipher);

        //-2 - -n
        enc_int_sub(sum,Enc_SubData,Enc_cipher);
        DataWrite(fp,Enc_cipher);
        
    }
    fclose(file);
    fclose(fp);
    return true;
}

//求解二元一次方程
void solveEquations(int n1, int m1, int n2, int m2,int *q3,int *q2) {
    // 计算分母 n2 * m1 - n1 * m2
    int denominator = n2 * m1 - n1 * m2;
    if (denominator == 0) {
        std::cerr << "The equations are dependent or inconsistent." << std::endl;
        return;
    }

    // 计算 y
    int y_numerator = -2*n1 + n2;
    if (y_numerator % denominator != 0) {
        std::cerr << "No integer solution for y." << std::endl;
        return;
    }
    int y = y_numerator / denominator;

    // 计算 x
    int x_numerator = m1 * y - 1;
    if (x_numerator % n1 != 0) {
        std::cerr << "No integer solution for x." << std::endl;
        return;
    }
    int x = x_numerator / n1;
    *q3 = x;
    *q2 = y;
}

//判断素数
bool isPrime(int num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;

    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }
    return true;
}

//在第六种情况下获取全域密文
bool get_cipher_from_1_to_n_mod(){
    int temp[32],data[32],addCnt,subCnt,modCnt;//记录加法操作数,减法操作数和mod操作数个数
    int exist_data[2*Max_N][32]; //存储加法和减法多个操作数
    int addIndex = 0,subIndex = 0,modIndex=0,findFlag = false,res,q3_or_q2;//记录当前判断的操作数位置
    int n1,n2,m1,m2,q4,q3,q2;//q4->mod,q3->add,q2->sub
    EncInt* Enc_zero = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* NMOD = (EncInt*)palloc0(sizeof(EncInt));//用于求解q4时存储nq3/nq2
    EncInt* Enc_sum = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* ModResult = (EncInt*)palloc0(sizeof(EncInt));
    EncInt add_array[Max_N+10],sub_array[Max_N+10],mod_array[Max_N+10]; //分别存储加法、减法和mod所有操作数
    EncInt NADD[Max_N+10],NADD1[Max_N+10],NSUB_1[Max_N+10];//分别存储nq3,nq3+1,mq2-1
    EncInt cipher[Max_N+10];//存储通过mod操作获取到的明密文对
    std::ifstream inputFile("/var/lib/postgresql/14/main/part.txt"); 
    for (int i = 0; i < 32; ++i) {
        inputFile >> data[i];
    }
    inputFile.close();
    //'1'的密文
    EncDataCopy(data,Enc_one);

    //add操作数
    if(!ExtractData2(6,1,exist_data)) return false;
    addCnt = cnt;
    for(int i = 0;i<addCnt;i++){
        for(int j = 0;j<32;j++){
            temp[j] = exist_data[i][j]; 
        }
        EncDataCopy(temp,&add_array[i]);
        enc_int_decrypt(&add_array[i],&res);
        printf("add操作数:%d\n",res);
    }

    //sub操作数
    if(!ExtractData2(6,2,exist_data)) return false;
    subCnt = cnt;
    for(int i = 0;i<subCnt;i++){
        for(int j = 0;j<32;j++){
            temp[j] = exist_data[i][j]; 
        }
        EncDataCopy(temp,&sub_array[i]);
        enc_int_decrypt(&sub_array[i],&res);
        printf("sub操作数:%d\n",res);
    }

    //提取加法、减法和mod操作数并验证签名
    ExtractAndVerify(6,1,2);
    ExtractAndVerify(6,2,2);
    ExtractAndVerify(6,9,2);

    //减法操作通过以后获取'0'的密文
    enc_int_sub(&sub_array[0],&sub_array[0],Enc_zero);
    
    //find q3 and q2
    while(!findFlag && addIndex<addCnt && subIndex<subCnt){
        //nq3
        EncDataCopy2(&add_array[addIndex],Enc_sum);
        EncDataCopy2(&add_array[addIndex],&NADD[0]);
        for(int i = 1;i<Max_N;i++){
            enc_int_add(&add_array[addIndex],Enc_sum,Enc_sum);
            EncDataCopy2(Enc_sum,&NADD[i]);
        }

        //nq3+1
        EncDataCopy2(Enc_one,Enc_sum);
        for(int i = 0;i<Max_N;i++){
            enc_int_add(&add_array[addIndex],Enc_sum,Enc_sum);
            EncDataCopy2(Enc_sum,&NADD1[i]);
        }

        //mq2-1
        enc_int_sub(&sub_array[subIndex],Enc_one,Enc_sum);
        EncDataCopy2(Enc_sum,&NSUB_1[0]);
        EncDataCopy2(Enc_one,Enc_sum);
        for(int i = 1;i<Max_N;i++){
            enc_int_sub(Enc_sum,&sub_array[subIndex],Enc_sum);
            EncDataCopy2(Enc_sum,&NSUB_1[i]);
        }
        for(int i = 1;i<Max_N;i++){
            enc_int_sub(&sub_array[subIndex],&NSUB_1[i],Enc_sum);
            EncDataCopy2(Enc_sum,&NSUB_1[i]);
        }


        //start cmp to find q2 and q3
    
        //test n1*q3 == m1*q2-1
        for(int i = 0;i<Max_N;i++){
            for(int j = 0;j<Max_N;j++){
                enc_int_cmp(&NADD[i],&NSUB_1[j],&res);
                // std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if(res == 0){
                    n1 = i+1;
                    m1 = j+1;
                    printf("%dq3 = %dq2 - 1\n",i+1,j+1);
                    break;
                }
            }
            if(res==0)
                break;
        }   
        
        //test n2*q3+1 == m2*q2-1
        //若找到n1*q3 == m1*q2-1，则进行下面的查找
        if(res==0){
            for(int i = 0;i<Max_N;i++){
                for(int j = 0;j<Max_N;j++){
                    enc_int_cmp(&NADD1[i],&NSUB_1[j],&res);
                    // std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    if(res == 0 && n1 * (j+1)!= m1 * (i+1)){
                        n2 = i+1;
                        m2 = j+1;
                        printf("%dq3+1 = %dq2 - 1\n",i+1,j+1);
                        break;
                    }
                }
                if(res==0)
                    break;
            } 
        }
        
        //若找到进行下面的步骤
        if(res==0){
            solveEquations(n1,m1,n2,m2,&q3,&q2);
            if(isPrime(q3)||(isPrime(q2) && q3 != 1)){
                findFlag = true;
            }
        }
        if(res!=0||((!isPrime(q3) && !isPrime(q2))||(isPrime(q2) && q3==1))){
            //先让减法操作数扫完
            if(subIndex<subCnt-1){
                subIndex++;
            }else{//否则加法操作数+1，减法从头开始
                if(addIndex<addCnt-1){ 
                    subIndex = 0;
                }
                addIndex++;
            }            
        }
    }

    if(subIndex==subCnt-1 && addIndex==addCnt){
        printf("Not Found!\n");
        return false;
    }else {
        printf("addIndex = %d , subIndex = %d\n",addIndex,subIndex);
        printf("add = %d,sub =  %d\n",q3,q2);
    }
    //end find q3 and q2

    //fine q4
    if(isPrime(q3)){
        EncDataCopy2(&add_array[addIndex],NMOD);
        q3_or_q2 = q3;
    } else{
        EncDataCopy2(&sub_array[subIndex],NMOD);
        q3_or_q2 = q2;
    }
    findFlag=false;
    if(!ExtractData2(6,9,exist_data)) return false;
    modCnt = cnt;
    for(int i = 0;i<modCnt;i++){
        for(int j = 0;j<32;j++){
            temp[j] = exist_data[i][j]; 
        }
        EncDataCopy(temp,&mod_array[i]);
        enc_int_decrypt(&mod_array[i],&res);
        printf("mod操作数:%d\n",res);
    }
    while(modIndex<modCnt){
        cnt = 1;
        enc_int_cmp(NMOD,&mod_array[modIndex],&res);
        //若q4不够大,则查找下一个q4
        if(res>=0)
            modIndex++;
        else{
            EncDataCopy2(NMOD,Enc_sum);

            do{
                enc_int_add(NMOD,Enc_sum,Enc_sum);
                enc_int_mod(Enc_sum,&mod_array[modIndex],ModResult);
                enc_int_cmp(ModResult,Enc_zero,&res);
                cnt++;
            }while(res!=0);

            enc_int_cmp(Enc_sum,&mod_array[modIndex],&res);
            if(res==0)
                modIndex++;
            else break;
        }
    }
    q4 =cnt;
    printf("q4 = %d,modIndex = %d\n",q4,modIndex);
    //end find q4

    //get 1~n
    EncDataCopy2(NMOD,Enc_sum);
    for(int i=1;i<q4;i++){
        int q = (i*q3_or_q2) % q4;
        enc_int_mod(Enc_sum,&mod_array[modIndex],ModResult);
        EncDataCopy2(ModResult,&cipher[q-1]);
        enc_int_add(NMOD,Enc_sum,Enc_sum);
    }

    for(int j = q4-q3-1;j<Max_N-q3;j++){
        enc_int_add(&add_array[addIndex],&cipher[j],&cipher[j+q3]); 
    }
    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
    if (file == NULL) {
        printf("无法打开文件。\n");
    } 
    for(int i = 1;i<Max_N;i++){
        for(int j = 0;j<IV_SIZE;j++){
            fprintf(file,"%d ",cipher[i].iv[j]);
            fflush(file);
        }
        for(int j = 0;j<TAG_SIZE;j++){
            fprintf(file,"%d ",cipher[i].tag[j]);
            fflush(file);
        }
        for(int j = 0;j<INT32_LENGTH;j++){
            fprintf(file,"%d ",cipher[i].data[j]);
            fflush(file);
        }
        fprintf(file,"\n");
        fflush(file);
    }
    fclose(file);
    return true; 
}

//在第一种,第二种,第四种,第六种情况下对比
bool binary_search(int CaseNum){
    // //验证签名
    if(!ExtractAndVerify(CaseNum,5,1))
        return false;

    std::ofstream("/var/lib/postgresql/14/main/crack.txt", std::ofstream::out).close();
    std::vector<std::vector<int>> data(Max_N, std::vector<int>(32));
    std::ifstream partFile("/var/lib/postgresql/14/main/part.txt");
    for (int i = 0; i < Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            partFile >> data[i][j];
        }
    }
    partFile.close();

    std::ifstream tempFile("/var/lib/postgresql/14/main/store.txt");
    std::vector<std::vector<int>> temp; 
    int number;

    while (tempFile >> number) { 
        std::vector<int> row;
        row.push_back(number); 
        for (int j = 1; j < 32; ++j) { 
            if (tempFile >> number) {
                row.push_back(number);
            } else {
                break;
            }
        }
        temp.push_back(row);
    }
    tempFile.close();

    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); // 打开文件以写入模式
    if (file == NULL) {
        printf("无法打开文件。\n");
    }
    for(int i = 0;i<Max_N;i++){
        int res;
        EncInt* knowData = (EncInt*)palloc0(sizeof(EncInt));
        for(int j = 0;j<IV_SIZE;++j){
            knowData->iv[j] = temp[i][j];
        }
        for(int j = 0;j<TAG_SIZE;++j){
            knowData->tag[j] = temp[i][j+IV_SIZE];
        }
        for(int j = 0;j<INT32_LENGTH;++j){
            knowData->data[j] = temp[i][j+IV_SIZE+TAG_SIZE];
        }
        enc_int_decrypt(knowData,&res);
        fprintf(file,"%d\n",res);
        fflush(file);
    }
           
    // for(int i = 0 ; i < temp.size();i++){ //带匹配的数据
    //     int low = 0,high = Max_N-1;
    //     while(low <= high){
    //         int res;
    //         int mid = (low+high)/2;
    //         EncInt* crackData = (EncInt*)palloc0(sizeof(EncInt));
    //         EncInt* knowData = (EncInt*)palloc0(sizeof(EncInt));
    //         for(int j = 0;j<IV_SIZE;++j){
    //             crackData->iv[j] = temp[i][j];
    //             knowData->iv[j] = data[mid][j];
    //         }
    //         for(int j = 0;j<TAG_SIZE;++j){
    //             crackData->tag[j] = temp[i][j+IV_SIZE];
    //             knowData->tag[j] = data[mid][j+IV_SIZE];
    //         }
    //         for(int j = 0;j<INT32_LENGTH;++j){
    //             crackData->data[j] = temp[i][j+IV_SIZE+TAG_SIZE];
    //             knowData->data[j] = data[mid][j+IV_SIZE+TAG_SIZE];
    //         }
            
    //         enc_int_cmp(crackData,knowData,&res);
    //         if(res == 0){
    //             // fprintf(file,"%d->%d\n",i+1,mid+1);
    //             fprintf(file,"%d\n",mid+1);
    //             fflush(file);
    //             break;
    //         }
    //         if(res == -1)
    //             high = mid-1;
    //         if(res == 1)
    //             low = mid+1;
    //     }
    //     if(low > high){
    //         fprintf(file,"%d->破解失败\n",i+1);
    //         fflush(file);
    //     }
    // }
    fclose(file);
    return true;
} 

//顺序对比，目前针对第三种情况
bool search(){
    int cmp_data[32];
    int cmpData,cmp_res;
    EncInt* Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Know_Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
    //验证签名
    if(!ExtractAndVerify(3,5,2))
        return false;
    if(!ExtractData(3,5,cmp_data)) return false;
    //cmp操作数
    EncDataCopy(cmp_data,Enc_CmpData);
    
    std::ofstream("/var/lib/postgresql/14/main/crack.txt", std::ofstream::out).close();
    std::vector<std::vector<int>> data(2*Max_N+1, std::vector<int>(32));
    std::ifstream partFile("/var/lib/postgresql/14/main/part.txt");
    for (int i = 0; i <= 2*Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            partFile >> data[i][j];
        }
    }
    partFile.close();

    std::ifstream tempFile("/var/lib/postgresql/14/main/store.txt");
    std::vector<std::vector<int>> temp; 
    int number;

    while (tempFile >> number) { 
        std::vector<int> row;
        row.push_back(number); 
        for (int j = 1; j < 32; ++j) { 
            if (tempFile >> number) {
                row.push_back(number);
            } else {
                break;
            }
        }
        temp.push_back(row);
    }
    tempFile.close();

    //获取cmp操作数的值
    for(int i = 0 ; i <= 2*Max_N ; i++){
        for(int j = 0 ; j < IV_SIZE ; ++j){
            Know_Enc_CmpData->iv[j] = data[i][j];
        }
        for(int j = 0;j<TAG_SIZE;++j){
            Know_Enc_CmpData->tag[j] = data[i][j+IV_SIZE];
        }
        for(int j = 0;j<INT32_LENGTH;++j){
            Know_Enc_CmpData->data[j] = data[i][j+IV_SIZE+TAG_SIZE];
        }
        enc_int_cmp(Enc_CmpData,Know_Enc_CmpData,&cmp_res);
        if(cmp_res==0){
            cmp_res = i<Max_N?i+1:Max_N-i;
            break;
        }
    }

    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); // 打开文件以写入模式
    if (file == NULL) {
        printf("无法打开文件。\n");
    }

    //start crack
    // FILE *file;
    // file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); // 打开文件以写入模式
    // if (file == NULL) {
    //     printf("无法打开文件。\n");
    // }
    for(int i = 0 ; i < temp.size();i++){
        int res,a,k,low,high,flag,CopyData[32];
        EncInt* crackData = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* knowData = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* tempData = (EncInt*)palloc0(sizeof(EncInt));
        for(int j=0;j<32;j++){
            CopyData[j] = temp[i][j];
        }
        EncDataCopy(CopyData,crackData);
        enc_int_cmp(Enc_CmpData,crackData,&res);
        if(res!=0){
            if(res>0) {
                low = 0;
                high = Max_N;
                flag = 1;
            }
            else{
                low = Max_N;
                high = 2*Max_N;
                flag = 0;
            }
            while(low <= high){
                int mid = (low+high)/2;
                for(int j=0;j<32;j++){
                    CopyData[j] = data[mid][j];
                }
                EncDataCopy(CopyData,knowData);
                enc_int_add(crackData,knowData,tempData);
                enc_int_cmp(Enc_CmpData,tempData,&res);
                if(res == 0){
                    res = mid<Max_N?mid+1:Max_N-mid;
                    res = cmp_res-res;
                    // printf("%d -> %d\n",i+1,res);
                    fprintf(file,"%d\n",res);
                    fflush(file);
                    break;
                }
                if(res==1){
                    if(flag == 1)
                        low = mid+1;
                    else
                        high = mid-1;
                }
                if(res==-1){
                    if(flag==1)
                        high = mid-1;
                    else
                        low = mid+1;
                }
            }
        }
        else{
            fprintf(file,"%d\n",cmp_res);
            fflush(file);
        }
        // if(res>0) k=0;
        // else k=Max_N;
        // for(;k <= 2*Max_N;k++){
        //     for(int j=0;j<32;j++){
        //         CopyData[j] = data[k][j];
        //     }
        //     EncDataCopy(CopyData,knowData);
        //     enc_int_add(crackData,knowData,tempData);
        //     enc_int_cmp(Enc_CmpData,tempData,&res);
        //     if(res == 0){
        //         res = k<Max_N?k+1:Max_N-k;
        //         res = cmp_res-res;
        //         if(OutCnt<20){
        //             write(std::to_string(i+1)+"->"+std::to_string(res)+"\n");
        //             OutCnt++;
        //         }
        //         // printf("%d->%d\n",i+1,res);
        //         fprintf(file,"%d\n",res);
        //         fflush(file);
        //         break;
        //     }
        // }
        }
    fclose(file);
    return true;
}

//针对第五种情况，采用计数器进行破解
bool Cntsearch(){
    int temp[32],res,cmp_data,sum_data,cnt0=0,cnt1=0,bulk_size = 1,number,y;
    std::vector<std::vector<int>> data(Max_N, std::vector<int>(32));
    std::vector<std::vector<int>> NData(Max_N+5, std::vector<int>(32));
    std::vector<std::vector<int>> storeData; 
    std::ifstream tempFile("/var/lib/postgresql/14/main/store.txt");
    std::ifstream partFile("/var/lib/postgresql/14/main/part.txt");
    std::ifstream NNFile("/var/lib/postgresql/14/main/NN.txt");
    EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData_N1 = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_N1 = (EncInt*)palloc0(sizeof(EncInt)); //-1
    EncInt* Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SumData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_Temp = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* KnowData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* crackData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* sum = (EncInt*)palloc0(sizeof(EncInt)); 
    EncInt* Enc_y = (EncInt*)palloc0(sizeof(EncInt)); 
    EncInt sum_array[256];

    //验证签名
    if(!ExtractAndVerify(5,5,2))
        return false;

    //赋值1-n
    for (int i = 0; i < Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            partFile >> data[i][j];
        }
    }
    partFile.close();
    //赋值-1 - -n
    for (int i = 0; i < Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            NNFile >> NData[i][j];
        }
    }
    NNFile.close();
    //获取存储数
    while (tempFile >> number) { 
        std::vector<int> row;
        row.push_back(number); 
        for (int j = 1; j < 32; ++j) { 
            if (tempFile >> number) {
                row.push_back(number);
            } else {
                break;
            }
        }
        storeData.push_back(row);
    }
    tempFile.close();

    //sub操作数
    if(!ExtractData(5,2,temp)) return false;
    EncDataCopy(temp,Enc_SubData);

    //cmp操作数
    if(!ExtractData(5,5,temp)) return false;
    EncDataCopy(temp,Enc_CmpData);
    for(int i=0;i<Max_N;i++){
        for(int j = 0;j<32;j++){
            temp[j] = data[i][j];
        }
        if(i==0){
            EncDataCopy(temp,Enc_one);
        }
        EncDataCopy(temp,KnowData);
        enc_int_cmp(Enc_CmpData,KnowData,&res);
        if(res==0)
        {
            cmp_data = i+1;
            break;
     
       }
    }

    enc_int_sub(Enc_SubData,Enc_one,Enc_SubData_N1); //q2-1
    enc_int_sub(Enc_SubData_N1,Enc_SubData,Enc_N1); //-1

    //SUM操作数
    if(!ExtractData(5,10,temp)) return false;
    EncDataCopy(temp,Enc_SumData);
    EncDataCopy2(Enc_SumData,&sum_array[0]);
    EncDataCopy2(Enc_SumData,sum);

    do{
        enc_int_cmp(Enc_CmpData,sum,&res);
        if(res>0){
            EncDataCopy2(Enc_one,&sum_array[bulk_size++]);
            enc_int_sum_bulk(bulk_size,sum_array,sum);
            if(bulk_size==256){
                EncDataCopy2(sum,&sum_array[0]);
                bulk_size=1;
            }
            cnt0++;
        }else if(res<0){
            EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);
            enc_int_sum_bulk(bulk_size,sum_array,sum);
            if(bulk_size==256){
                EncDataCopy2(sum,&sum_array[0]);
                bulk_size=1;
            }
            cnt1--;
        }
        else{
            break;
        }
    }while(res!=0);
    
    sum_data = cmp_data-cnt0-cnt1;
    y = cnt0+cnt1;
    EncDataCopy2(Enc_SumData,&sum_array[0]);
    bulk_size = 1;
    //enc_y
    for(int j = 0;j<32;j++){
        temp[j] = NData[sum_data][j];
    }
    EncDataCopy(temp,Enc_y);
    EncDataCopy2(Enc_y,&sum_array[bulk_size++]);

    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); // 打开文件以写入模式
    if (file == NULL) {
        printf("无法打开文件。\n");
    }

    //start crack
    for(int i = 0;i<storeData.size();i++){
        cnt0 = 0,cnt1 = 0,bulk_size=0;
        for(int j = 0;j<32;j++){
            temp[j] = storeData[i][j];
        }
        EncDataCopy2(Enc_SumData,&sum_array[bulk_size++]);
        EncDataCopy2(Enc_y,&sum_array[bulk_size++]);
        EncDataCopy(temp,crackData);
        EncDataCopy2(crackData,&sum_array[bulk_size++]);
        do{
            enc_int_cmp(Enc_CmpData,crackData,&res);
            if(res > 0){ 
                EncDataCopy2(Enc_one,&sum_array[bulk_size++]);
                enc_int_sum_bulk(bulk_size,sum_array,crackData);
                if(bulk_size==256){
                    EncDataCopy2(crackData,&sum_array[0]);
                    bulk_size=1;
                }
                cnt0--;
            }else if(res < 0){
                EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);
                enc_int_sum_bulk(bulk_size,sum_array,crackData);
                if(bulk_size==256){
                    EncDataCopy2(crackData,&sum_array[0]);
                    bulk_size=1;
                }
                cnt1++;
            }
            else{
                break;
            }
        }while(res!=0);
        // printf("%d -> %d\n",i+1,cmp_data+cnt0+cnt1);
        fprintf(file,"%d\n",cmp_data+cnt0+cnt1);
        fflush(file);
    }
    fclose(file);
    return true;
}

//针对第五种情况，采用计数器进行破解
bool SumSearch(){
    int temp[32],res,cmp_data,sum_data,cnt0=0,cnt1=0,bulk_size = 1,number,y;
    std::vector<std::vector<int>> data(Max_N, std::vector<int>(32));
    std::vector<std::vector<int>> NData(Max_N+5, std::vector<int>(32));
    std::vector<std::vector<int>> storeData; 
    std::ifstream tempFile("/var/lib/postgresql/14/main/store.txt");
    std::ifstream partFile("/var/lib/postgresql/14/main/part.txt");
    std::ifstream NNFile("/var/lib/postgresql/14/main/NN.txt");
    EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SubData_N1 = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_N1 = (EncInt*)palloc0(sizeof(EncInt)); //-1
    EncInt* Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_SumData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* Enc_Temp = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* KnowData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* crackData = (EncInt*)palloc0(sizeof(EncInt));
    EncInt* sum = (EncInt*)palloc0(sizeof(EncInt)); 
    EncInt* Enc_y = (EncInt*)palloc0(sizeof(EncInt)); 
    EncInt sum_array[256];

    //验证签名
    if(!ExtractAndVerify(5,5,2))
        return false;

    //赋值1-n
    for (int i = 0; i < Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            partFile >> data[i][j];
        }
    }
    partFile.close();
    //赋值-1 - -n
    for (int i = 0; i < Max_N; ++i) {
        for (int j = 0; j < 32; ++j) {
            NNFile >> NData[i][j];
        }
    }
    NNFile.close();
    //获取存储数
    while (tempFile >> number) { 
        std::vector<int> row;
        row.push_back(number); 
        for (int j = 1; j < 32; ++j) { 
            if (tempFile >> number) {
                row.push_back(number);
            } else {
                break;
            }
        }
        storeData.push_back(row);
    }
    tempFile.close();

    //sub操作数
    if(!ExtractData(5,2,temp)) return false;
    EncDataCopy(temp,Enc_SubData);

    //cmp操作数
    if(!ExtractData(5,5,temp)) return false;
    EncDataCopy(temp,Enc_CmpData);
    for(int i=0;i<Max_N;i++){
        for(int j = 0;j<32;j++){
            temp[j] = data[i][j];
        }
        if(i==0){
            EncDataCopy(temp,Enc_one);
        }
        EncDataCopy(temp,KnowData);
        enc_int_cmp(Enc_CmpData,KnowData,&res);
        if(res==0)
        {
            cmp_data = i+1;
            break;
     
       }
    }

    enc_int_sub(Enc_SubData,Enc_one,Enc_SubData_N1); //q2-1
    enc_int_sub(Enc_SubData_N1,Enc_SubData,Enc_N1); //-1

    //SUM操作数
    if(!ExtractData(5,10,temp)) return false;
    EncDataCopy(temp,Enc_SumData);
    EncDataCopy2(Enc_SumData,&sum_array[0]);
    EncDataCopy2(Enc_SumData,sum);

    do{
        enc_int_cmp(Enc_CmpData,sum,&res);
        if(res>0){
            EncDataCopy2(Enc_one,&sum_array[bulk_size++]);
            enc_int_sum_bulk(bulk_size,sum_array,sum);
            if(bulk_size==256){
                EncDataCopy2(sum,&sum_array[0]);
                bulk_size=1;
            }
            cnt0++;
        }else if(res<0){
            EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);
            enc_int_sum_bulk(bulk_size,sum_array,sum);
            if(bulk_size==256){
                EncDataCopy2(sum,&sum_array[0]);
                bulk_size=1;
            }
            cnt1--;
        }
        else{
            break;
        }
    }while(res!=0);
    
    sum_data = cmp_data-cnt0-cnt1;
    y = cnt0+cnt1;
    EncDataCopy2(Enc_SumData,&sum_array[0]);
    bulk_size = 1;
    //enc_y
    for(int j = 0;j<32;j++){
        temp[j] = NData[sum_data][j];
    }
    EncDataCopy(temp,Enc_y);
    EncDataCopy2(Enc_y,&sum_array[bulk_size++]);

    FILE *file;
    file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); // 打开文件以写入模式
    if (file == NULL) {
        printf("无法打开文件。\n");
    }

    //start crack
    for(int i = 0;i<storeData.size();i++){
        cnt0 = 0,bulk_size=2;
        for(int j = 0;j<32;j++){
            temp[j] = storeData[i][j];
        }
        EncDataCopy(temp,crackData);
        EncDataCopy2(crackData,&sum_array[bulk_size++]);
        enc_int_cmp(Enc_CmpData,crackData,&res);
        for(int k=0;k<Max_N;k++){
            int resp;
            if(res<=0){
                for(int m=0;m<32;m++){
                    temp[m] = NData[k][m];
                }
            }else{  
                for(int m=0;m<32;m++){
                    temp[m] = data[k][m];
                }
            }
            EncDataCopy(temp,crackData);
            EncDataCopy2(crackData,&sum_array[bulk_size]);
            enc_int_sum_bulk(4,sum_array,sum);
            enc_int_cmp(Enc_CmpData,sum,&resp);
            if(resp==0){
                cnt0 = (res>0?k+1:k);
                break;
            }
        }
        // printf("%d -> %d\n",i+1,cmp_data+cnt0);
        fprintf(file,"%d\n",cmp_data+cnt0);
        fflush(file);
    }
    fclose(file);
    return true;
}


// int main(){
//     printf("\033[1;31m谨记确保运行的crack是在没开启record开关情况下编译的,否则会报Segmentation fault!\033[0m\n");
//     printf("\033[1;31m原因是record.cpp中append_signature_to_file文件指针为空!\033[0m\n");
//     int resp,choice;
//     printf("输入待破解场景序号：");
//     scanf("%d",&choice);
//     clock_t start = clock();
//     switch(choice){
//         case 1:
//         case 2:
//             // printf("正在加载内存表数据……\n");
//             // fromLog_Store(choice);
//             // printf("=============获取密文'1'……===============\n");
//             // if(get_cipher_one(choice)){
//             //     printf("密文1获取成功!\n");
//             // }
//             // else{
//             //     printf("密文1获取失败,破解失败\n");
//             //     return 0;
//             // }
//             // printf("获取密文'2'……'n'\n");
//             // if(get_cipher_from_1_to_n(choice)){
//             //     printf("全域密文获取成功!\n");
//             // }else{
//             //     printf("全域密文获取失败,破解失败\n");
//             //     return 0;
//             // }
//             // printf("破解中，请等待……\n");
//             if(binary_search(choice)){
//                 clock_t end = clock(); 
//                 double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
//                 printf("破解用时%f\n",elapsed_secs);
//             }else{
//                 printf("破解失败\n");
//             }
//             break;
//         case 3:
//             // printf("正在加载内存表数据……\n");
//             // fromLog_Store(choice);
//             // printf("=============获取密文'1'……===============\n");
//             // if(get_cipher_one(choice)){
//             //     printf("密文1获取成功!\n");
//             // }
//             // else{
//             //     printf("密文1获取失败,破解失败\n");
//             //     return 0;
//             // }
//             // printf("获取密文'2'……'n'\n");
//             // if(get_cipher_from_1_to_n(choice)){
//             //     printf("1-n全域密文获取成功!\n");
//             // }else{
//             //     printf("1-n全域密文获取失败,破解失败\n");
//             //     return 0;
//             // }
//             // if(get_cipher_from_n1_nn(choice)){
//             //     printf("0-nn全域密文获取成功!\n");
//             // }else{
//             //     printf("0-nn全域密文获取失败,破解失败\n");
//             //     return 0;
//             // }
//             // printf("破解中，请等待……\n");
//             if(search()){
//                 clock_t end = clock(); 
//                 double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
//                 printf("破解用时%f\n",elapsed_secs);
//             }else{
//                 printf("破解失败\n");
//             }
//             break;
//         case 4:
//             printf("正在加载内存表数据……\n");
//             fromLog_Store(choice);
//             printf("=============获取密文'1'……===============\n");
//             if(get_cipher_one(choice)){
//                 printf("密文1获取成功!\n");
//             }
//             else{
//                 printf("密文1获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("获取密文'-n'……'n'\n");
//             if(get_cipher_from_1_to_n_sum(choice)){
//                 printf("-n-n全域密文获取成功!\n");
//             }else{
//                 printf("-n-n全域密文获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("破解中，请等待……\n");
//             if(binary_search(choice)){
//                 clock_t end = clock(); 
//                 double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
//                 printf("破解用时%f\n",elapsed_secs);
//             }else{
//                 printf("破解失败\n");
//             }
//             break;
//         case 5:
//             printf("正在加载内存表数据……\n");
//             fromLog_Store(choice);
//             printf("=============获取密文'1'……===============\n");
//             if(get_cipher_one(choice)){
//                 printf("密文1获取成功!\n");
//             }
//             else{
//                 printf("密文1获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("获取密文'-n'……'n'\n");
//             if(get_cipher_from_1_to_n_sum(choice)){
//                 printf("-n-n全域密文获取成功!\n");
//             }else{
//                 printf("-n-n全域密文获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("破解中，请等待……\n");
//             if(SumSearch()){
//                 clock_t end = clock(); 
//                 double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
//                 printf("破解用时%f\n",elapsed_secs);
//             }else{
//                 printf("破解失败\n");
//             }
//             break;
//         case 6:
//             printf("正在加载内存表数据……\n");
//             fromLog_Store(choice);
//             printf("=============获取密文'1'……===============\n");
//             if(get_cipher_one(choice)){
//                 printf("密文1获取成功!\n");
//             }
//             else{
//                 printf("密文1获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("获取密文'2'……'n'\n");
//             if(get_cipher_from_1_to_n_mod()){
//                 printf("全域密文获取成功!\n");
//             }else{
//                 printf("全域密文获取失败,破解失败\n");
//                 return 0;
//             }
//             printf("破解中，请等待……\n");
//             if(binary_search(choice)){
//                 clock_t end = clock(); 
//                 double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
//                 printf("破解用时%f\n",elapsed_secs);
//             }else{
//                 printf("破解失败\n");
//             }
//             break;
//         default:
//             printf("输入的序号有问题!\n");
//             break;
//     }
// }

int main(){
    printf("\033[1;31m谨记确保运行的crack是在没开启record开关情况下编译的,否则会报Segmentation fault!\033[0m\n");
    printf("\033[1;31m原因是record.cpp中append_signature_to_file文件指针为空!\033[0m\n");
    binary_search(1);
    return 0;
}



