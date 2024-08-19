#include <gtkmm.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
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
#include <vector>
#include <cstdio>
#include <chrono>
#include <thread>
#include <ctime>
#include <rr_utils.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#define Max_N 2500000
int cnt = 0;// Used for multiple extraction operations and comparison of the value of q4
const char* public_key_file = "/var/lib/postgresql/14/main/public_key.pem";

class MyWindow : public Gtk::Window {
public:
    MyWindow() {
        set_title("Substitution and Replay Attacks");
        set_default_size(900, 650);
        // maximize();
        button.set_label("Select Log File");
        button.set_hexpand(true); 
        button.signal_clicked().connect(sigc::bind(sigc::mem_fun(*this, &MyWindow::on_button_clicked), 1));
        
        databutton.set_label("Select Data File");
        databutton.set_hexpand(true);
        databutton.signal_clicked().connect(sigc::bind(sigc::mem_fun(*this, &MyWindow::on_button_clicked), 2));

        // Create a horizontal box to place file selection buttons
        hbox_files.set_spacing(10); 
        hbox_files.pack_start(button, Gtk::PACK_EXPAND_WIDGET); 
        hbox_files.pack_start(databutton, Gtk::PACK_EXPAND_WIDGET); 

        // Create a horizontal box to place radio buttons
        hbox_radio_buttons.set_spacing(10); 
        hbox_radio_buttons.set_homogeneous(true);
        hbox_radio_buttons.set_margin_top(0);
        hbox_radio_buttons.set_margin_bottom(0); 
        for (int i = 1; i <= 6; ++i) {
            std::string label = std::to_string(i);
            radio_buttons[i].set_label(label);
            radio_buttons[i].signal_clicked().connect(sigc::bind<int>(sigc::mem_fun(*this, &MyWindow::on_radio_button_clicked), i));
            if (i != 1) {
                radio_buttons[i].join_group(radio_buttons[1]); 
                radio_buttons[i].set_active(false); 
            }
            hbox_radio_buttons.pack_start(radio_buttons[i], Gtk::PACK_SHRINK);
        }

        // Set up Confirm, Clear, and Cancel buttons
        confirm_button.set_label("Confirm");
        confirm_button.set_sensitive(false); // The "Confirm" button is initially disabled
        confirm_button.signal_clicked().connect(sigc::mem_fun(*this, &MyWindow::on_confirm_button_clicked));

        clear_button.set_label("Clear");
        clear_button.signal_clicked().connect(sigc::mem_fun(*this, &MyWindow::on_clear_button_clicked));

        cancel_button.set_label("Cancel");
        cancel_button.set_sensitive(false); 
        cancel_button.signal_clicked().connect(sigc::mem_fun(*this, &MyWindow::on_cancel_button_clicked));

        
        separator_top.set_orientation(Gtk::ORIENTATION_HORIZONTAL);
        separator_top.set_margin_top(0); 
        separator_top.set_margin_bottom(0); 

        separator_middle.set_orientation(Gtk::ORIENTATION_HORIZONTAL);
        separator_middle.set_margin_top(0); 
        separator_middle.set_margin_bottom(0); 

        // label.set_text("Label with Background Image");
        label.set_margin_top(20); 
        label.set_margin_bottom(20); 

        // Create a ScrolledWindow to place a Label
        scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC); 
        scrolled_window.add(label); 

        // Load and set a background image
        Glib::RefPtr<Gdk::Pixbuf> pixbuf = Gdk::Pixbuf::create_from_file("/root/HEDB/2.png");
        if (pixbuf) {
            Gtk::EventBox event_box;
            event_box.override_background_color(Gdk::RGBA()); 
            Gtk::Image image(pixbuf);
            event_box.add(image); 
            vbox.pack_start(event_box, Gtk::PACK_SHRINK);
            vbox.pack_start(scrolled_window, Gtk::PACK_EXPAND_WIDGET); 
        } else {
            std::cerr << "Failed to load image /root/HEDB/2.png" << std::endl;
        }

        hbox_buttons.set_spacing(10); 
        hbox_buttons.pack_start(clear_button, Gtk::PACK_SHRINK); 
        hbox_buttons.pack_end(confirm_button, Gtk::PACK_SHRINK); 
        hbox_buttons.pack_end(cancel_button, Gtk::PACK_SHRINK); 

        vbox.set_margin_top(20); 
        vbox.set_margin_bottom(20); 
        vbox.pack_start(hbox_files, Gtk::PACK_SHRINK); 
        vbox.pack_start(separator_top, Gtk::PACK_SHRINK); 
        vbox.pack_start(hbox_radio_buttons, Gtk::PACK_SHRINK);
        vbox.pack_start(separator_middle, Gtk::PACK_SHRINK); 
        vbox.pack_start(hbox_buttons, Gtk::PACK_SHRINK); 

        add(vbox);
        auto css_provider = Gtk::CssProvider::create();
        try {
            css_provider->load_from_path("/root/HEDB/src/integrity_zone/1.css");
            auto screen = Gdk::Screen::get_default();
            auto style_context = get_style_context();
            style_context->add_provider_for_screen(screen, css_provider, GTK_STYLE_PROVIDER_PRIORITY_USER);

            label.get_style_context()->add_class("textview");
            button.get_style_context()->add_class("button");
            databutton.get_style_context()->add_class("button");
            confirm_button.get_style_context()->add_class("button");
            clear_button.get_style_context()->add_class("button");
            cancel_button.get_style_context()->add_class("button");

            for (int i = 1; i <= 6; ++i) {
                radio_buttons[i].get_style_context()->add_class("button");
            }

            get_style_context()->add_class("window-title");

            show_all_children();
        } catch(const Gtk::CssProviderError& ex) {
            std::cerr << "Failed to load CSS: " << ex.what() << std::endl;
        } catch(const std::exception& ex) {
            std::cerr << "Exception occurred: " << ex.what() << std::endl;
        }
    }

protected:
    // Verify the signature
    bool verify_signature_base64(const char* message, const char* pub_filename, const char* signatureContent) {
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

        // Create and initialize EVP_MD_CTX for signature verification.
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pubkey);
        bool result = EVP_DigestVerify(md_ctx, buffer.data(), buffer.size(), reinterpret_cast<const unsigned char*>(message), strlen(message)) == 1;

        BIO_free_all(bio);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);

        return result;
    }

    // Extract the corresponding numerical signature content
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

    // Extract the numerical signature content for the SUM operator
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

    // Place the data from the array into the Enc_int variable
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

    // Check if the data array already exists in exist_data
    bool isDataInExistData(const int exist_data[200][32], const int data[32]) {
        for (int i = 0; i < 200; ++i) {
            if (std::memcmp(exist_data[i], data, 32 * sizeof(int)) == 0) {
                return true; 
            }
        }
        return false; 
    }

    // Obtain the operands
    bool ExtractData(int CaseNum,int ops,int *data){
        std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
        std::ifstream file(filepath); 
        std::string line;
        std::string cmp="operator:"+std::to_string(ops);
        std::string operations[] = {"PLUS", "MINUS", "MULT", "DIV","CMP","ENC","DEC","EXP","MOD","SUM_BULK"};
        bool find = false;

        if (!file) {
            write("Error: Unable to open file:"+file_path+"\n");
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
            write("Error: cannot find "+operations[ops-1]+" data!\n");
        }
        return find;
    }

    // In the sixth case, obtain all operand
    bool ExtractData2(int CaseNum,int ops,int exist_data[200][32]){
        cnt = 0;
        std::string filepath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(CaseNum)+".txt";
        std::ifstream file(filepath); 
        std::string line;
        std::string cmp="operator:"+std::to_string(ops);
        std::string operations[] = {"PLUS", "MINUS", "MULT", "DIV","CMP","ENC","DEC","EXP","MOD","SUM_BULK"};
        int data[32];
        bool find = false;
        if (!file) {
            write("Error: Unable to open file:"+file_path+"\n");
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
            write("Error: cannot find "+operations[ops-1]+" data!\n");
        }
        return find;
    }

    // Extract the numerical signature and verify it
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
                write("The signature content for the "+operations[ops-1]+" operator has been successfully extracted:");
                write(signature+"\n");
            } else{
                write("Failed to extract content of the "+operations[ops-1]+" operator signature~\n");
                return false;
            }
        }else{
            if(ExtractSumSignature(CaseNum, signature)){
                write("The signature content for the "+operations[ops-1]+" operator has been successfully extracted:");
                write(signature+"\n");
            } else{
                write("Failed to extract content of the "+operations[ops-1]+" operator signature~\n");
                return false;
            }
        }
        
        if(verify_signature_base64(message.c_str(),public_key_file,signature.c_str())){
            write("The signature verification for the "+ operations[ops-1]+" operator has passed!\n");
            return true;
        } else{
            write("The signature verification for the "+ operations[ops-1]+" operator has failed~\n");
            return false;
        }

        return true;
    }

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

    bool fromLog_Store(){
        int OutCnt=0;
        std::ifstream inputFile(data_file_path);
        if (!inputFile) {
            write("Error: Unable to open input file.");
            return false;
        }
        write("Loading in-memory table data......\n");
        std::string outputFilePath = "/var/lib/postgresql/14/main/store.txt";
        std::ofstream(outputFilePath,std::ofstream::out).close();
        std::ofstream outputFile(outputFilePath);
        if (!outputFile) {
            write("Error: Unable to open output file.");
            return false;
        }

        std::string line;
        while (std::getline(inputFile, line)) {
            outputFile << line << std::endl;
            if(OutCnt<20)
                write(line+"\n");
            OutCnt++;
        }

        inputFile.close();
        outputFile.close();
        write("……\n In-memory table data loaded successfully. The save path is: /var/lib/postgresql/14/main/store.txt,total: "+std::to_string(OutCnt)+"records!\n");
        return true;
    }

    // Use the division operator to obtain '1'  
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
        
        EncDataCopy(data,div_left);
        EncDataCopy(data,div_right);
        enc_int_div(div_left, div_right, enc_one);
        std::ofstream("/var/lib/postgresql/14/main/part.txt",std::ofstream::out).close();
        FILE * file;
        file = fopen("/var/lib/postgresql/14/main/part.txt","a");
        if(file==NULL) {
            printf("cannot open file.\n");
            return false;
        }
     
        DataWrite(file,enc_one);
        fclose(file);
        return true;
    }

    // Use addition to generate global ciphertexts for 2 to n
    bool get_cipher_from_1_to_n(int CaseNum){
        int data[32];
        
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
            printf("Unable to open the file.\n");
            return false;
        }
        EncDataCopy(data,add_left);
        EncDataCopy(data,add_res);
 
        for(int i = 1; i <Max_N; i++){
            int error= enc_int_add(add_left, add_res, add_res);
            DataWrite(file,add_res);
        }  
        fclose(file);
        return true;
    }

    // Use the subtraction operator to obtain ciphertexts for -1 to -n
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

        EncDataCopy(Enc_one_Data,Enc_one);

        // Ciphertext of the sub (subtraction) operand
        if(!ExtractData(CaseNum,2,sub_data)) return false;
        EncDataCopy(sub_data,Enc_SubData);
        enc_int_add(Enc_one,Enc_SubData,Enc_SubData_Add_1);
      
        if(!ExtractAndVerify(CaseNum,2,2))
            return false;

        enc_int_sub(Enc_SubData,Enc_SubData_Add_1,Enc_N1);
        enc_int_sub(Enc_SubData,Enc_SubData,Enc_zero);
        enc_int_sub(Enc_SubData,Enc_SubData,add_res);
        FILE *file;
        file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
        if (file == NULL) {
            printf("Unable to open the file.\n");
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

    // In the fourth and fifth cases, obtain global ciphertexts
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

        EncDataCopy(data,Enc_one);
        // Obtain the subtraction operand and verify the subtraction operation
        if(CaseNum == 5){
            if(!ExtractData(5,2,data)) return false;
            EncDataCopy(data,Enc_SubData);
            if(!ExtractAndVerify(CaseNum,2,2))
                return false;
        }
        

        // Obtain the sum operand
        if(!ExtractData(5,10,data)) return false;
        EncDataCopy(data,Enc_SumData);
        if(!ExtractAndVerify(CaseNum,10,2)) 
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
            printf("Unable to open the file.\n");
        }
        std::ofstream("/var/lib/postgresql/14/main/NN.txt",std::ofstream::out).close(); 
        FILE *fp;
        fp = fopen("/var/lib/postgresql/14/main/NN.txt", "a");
        if (fp == NULL) {
            printf("Unable to open the file.\n");
        } 
        //0
        // DataWrite(fp,Enc_zero);
        //-1
        DataWrite(fp,Enc_N1);
    
        for(int i=2;i<=Max_N;i++){
            EncDataCopy2(Enc_N1,&sum_array[bulk_size++]);
            enc_int_sum_bulk(bulk_size,sum_array,sum);
            if(bulk_size==256){
                EncDataCopy2(sum,&sum_array[0]);
                bulk_size=1;
            }        
            // 2-n
            enc_int_sub(Enc_SubData,sum,Enc_cipher);
            DataWrite(file,Enc_cipher);

            // -2 - -n
            enc_int_sub(sum,Enc_SubData,Enc_cipher);
            DataWrite(fp,Enc_cipher);
            
        }
        fclose(file);
        fclose(fp);
        return true;
    }

    // Solve a linear equation with two variables
    void solveEquations(int n1, int m1, int n2, int m2,int *q3,int *q2) {
        int denominator = n2 * m1 - n1 * m2;
        if (denominator == 0) {
            std::cerr << "The equations are dependent or inconsistent." << std::endl;
            return;
        }

        int y_numerator = -2*n1 + n2;
        if (y_numerator % denominator != 0) {
            std::cerr << "No integer solution for y." << std::endl;
            return;
        }
        int y = y_numerator / denominator;

        int x_numerator = m1 * y - 1;
        if (x_numerator % n1 != 0) {
            std::cerr << "No integer solution for x." << std::endl;
            return;
        }
        int x = x_numerator / n1;
        *q3 = x;
        *q2 = y;
    }

    bool isPrime(int num) {
        if (num <= 1) return false;
        if (num <= 3) return true;
        if (num % 2 == 0 || num % 3 == 0) return false;

        for (int i = 5; i * i <= num; i += 6) {
            if (num % i == 0 || num % (i + 2) == 0) return false;
        }
        return true;
    }

    // In the sixth case, obtain global ciphertexts
    bool get_cipher_from_1_to_n_mod(){
        int temp[32],data[32],addCnt,subCnt,modCnt;// Record the number of addition, subtraction, and modulus operands.
        int exist_data[200][32]; // Store multiple addition and subtraction operands.
        // std::vector<std::vector<int>> exist_data(Max_N, std::vector<int>(32));
        int addIndex = 0,subIndex = 0,modIndex=0,findFlag = false,res,q3_or_q2;
        int n1,n2,m1,m2,q4,q3,q2;//q4->mod,q3->add,q2->sub
        EncInt* Enc_zero = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* Enc_one = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* NMOD = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* Enc_sum = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* ModResult = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* ncipher = (EncInt*)palloc0(sizeof(EncInt));
        std::vector<EncInt> add_array(Max_N+10);
        std::vector<EncInt> sub_array(Max_N+10);
        std::vector<EncInt> mod_array(Max_N+10);
        std::vector<EncInt> NADD(Max_N+10);
        std::vector<EncInt> NADD1(Max_N+10);
        std::vector<EncInt> NSUB_1(Max_N+10);
        std::vector<EncInt> cipher(2*Max_N);
        // EncInt add_array[Max_N+10],sub_array[Max_N+10],mod_array[Max_N+10]; 
        // EncInt NADD[Max_N+10],NADD1[Max_N+10],NSUB_1[Max_N+10];//nq3,nq3+1,mq2-1
        // EncInt cipher[Max_N+10];
        std::ifstream inputFile("/var/lib/postgresql/14/main/part.txt"); 
        for (int i = 0; i < 32; ++i) {
            inputFile >> data[i];
        }
        inputFile.close();

        EncDataCopy(data,Enc_one);
        // add operands
        if(!ExtractData2(6,1,exist_data)) return false;
        addCnt = cnt;
        write("Number of PLUS operands in the log:"+std::to_string(addCnt)+"\n");
        for(int i = 0;i<addCnt;i++){
            for(int j = 0;j<32;j++){
                temp[j] = exist_data[i][j]; 
            }
            EncDataCopy(temp,&add_array[i]);
            enc_int_decrypt(&add_array[i],&res);
            printf("%d\n",res);
        }

        // sub opearands
        if(!ExtractData2(6,2,exist_data)) return false;
        subCnt = cnt;
        write("Number of SUB operands in the log:"+std::to_string(subCnt)+"\n");
        for(int i = 0;i<subCnt;i++){
            for(int j = 0;j<32;j++){
                temp[j] = exist_data[i][j]; 
            }
            EncDataCopy(temp,&sub_array[i]);
        }

        if(!ExtractData2(6,9,exist_data)) return false;
        modCnt = cnt;
        write("Number of MOD operands in the log:"+std::to_string(modCnt)+"\n");
        for(int i = 0;i<modCnt;i++){
            for(int j = 0;j<32;j++){
                temp[j] = exist_data[i][j]; 
            }
            EncDataCopy(temp,&mod_array[i]);
        }

        // Extract the addition, subtraction, and modulus operands and verify the signature.
        ExtractAndVerify(6,1,2);
        ExtractAndVerify(6,2,2);
        ExtractAndVerify(6,9,2);
        enc_int_sub(&sub_array[0],&sub_array[0],Enc_zero);
        write("q4-->MOD Data,q3-->PLUS Data,q2-->SUB Data\n");

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
                        write(std::to_string(i+1)+"q3 = "+std::to_string(j+1)+"q2 - 1\n");
                        printf("%dq3 = %dq2 - 1\n",i+1,j+1);
                        break;
                    }
                    if(res<0)
                        break;
                }
                if(res==0)
                    break;
            }   
            
            //test n2*q3+1 == m2*q2-1
            // If find n1*q3 == m1*q2-1, proceed with the following search
            if(res==0){
                for(int i = 0;i<Max_N;i++){
                    for(int j = 0;j<Max_N;j++){
                        enc_int_cmp(&NADD1[i],&NSUB_1[j],&res);
                        // std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        if(res == 0 && n1 * (j+1)!= m1 * (i+1)){
                            n2 = i+1;
                            m2 = j+1;
                            write(std::to_string(i+1)+"q3+1 = "+std::to_string(j+1)+"q2 - 1\n");
                            printf("%dq3+1 = %dq2 - 1\n",i+1,j+1);
                            break;
                        }
                        if(res<0)
                            break; 
                    }
                    if(res==0)
                        break;
                } 
            }
            
            if(res==0){
                solveEquations(n1,m1,n2,m2,&q3,&q2);
                if(isPrime(q3)||(isPrime(q2) && q3 != 1)){
                    findFlag = true;
                }
            }
            if(res!=0||((!isPrime(q3) && !isPrime(q2))||(isPrime(q2) && q3==1))){
                // First, complete the scan for the subtraction operands
                if(subIndex<subCnt-1){
                    subIndex++;
                }else{// Otherwise, increment the addition operand by 1 and restart the subtraction from the beginning
                    if(addIndex<addCnt-1){ 
                        subIndex = 0;
                    }
                    addIndex++;
                }            
            }
        }

        if(subIndex==subCnt-1 && addIndex==addCnt){
            write("Not Found!\n");
            return false;
        }else {
            write("PLUS Index = "+std::to_string(addIndex)+",q3 =  "+std::to_string(q3)+"\n");
            write("SUB Index = "+std::to_string(subIndex)+",q2 =  "+std::to_string(q2)+"\n");
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
        while(modIndex<modCnt){
            cnt = 1;
            enc_int_cmp(NMOD,&mod_array[modIndex],&res);
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
        write("MOD Index = "+std::to_string(modIndex)+",q4 =  "+std::to_string(q4)+"\n");
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

        for(int j = q4-q3-1;j<q2+Max_N-q3;j++){
            enc_int_add(&add_array[addIndex],&cipher[j],&cipher[j+q3]); 
        }
        FILE *file;
        file = fopen("/var/lib/postgresql/14/main/part.txt", "a");
        if (file == NULL) {
            printf("Unable to open the file.\n");
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
        //get -n~-1
        std::ofstream("/var/lib/postgresql/14/main/NN.txt", std::ofstream::out).close();
        FILE *fp;
        fp = fopen("/var/lib/postgresql/14/main/NN.txt", "a");
        if (fp == NULL) {
            printf("Unable to open the file.\n");
        } 
        for(int j = q2;j<q2+Max_N;j++){
            enc_int_sub(&sub_array[subIndex],&cipher[j],ncipher);
            for(int j = 0;j<IV_SIZE;j++){
                fprintf(fp,"%d ",ncipher->iv[j]);
                fflush(fp);
            }
            for(int j = 0;j<TAG_SIZE;j++){
                fprintf(fp,"%d ",ncipher->tag[j]);
                fflush(fp);
            }
            for(int j = 0;j<INT32_LENGTH;j++){
                fprintf(fp,"%d ",ncipher->data[j]);
                fflush(fp);
            }
            fprintf(fp,"\n");
            fflush(fp);
        }
        return true; 
    }

    // Compare in the first, second, fourth, and sixth cases
    bool binary_search(int CaseNum){
        if(!ExtractAndVerify(CaseNum,5,1))
            return false;

        std::ofstream("/var/lib/postgresql/14/main/crack.txt", std::ofstream::out).close();
        int OutCnt=0;
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
        file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); 
        if (file == NULL) {
            printf("Unable to open the file.\n");
        }
        for(int i = 0 ; i < temp.size();i++){ 
            int low = 0,high = Max_N-1;
            while(low <= high){
                int res;
                int mid = (low+high)/2;
                EncInt* crackData = (EncInt*)palloc0(sizeof(EncInt));
                EncInt* knowData = (EncInt*)palloc0(sizeof(EncInt));
                for(int j = 0;j<IV_SIZE;++j){
                    crackData->iv[j] = temp[i][j];
                    knowData->iv[j] = data[mid][j];
                }
                for(int j = 0;j<TAG_SIZE;++j){
                    crackData->tag[j] = temp[i][j+IV_SIZE];
                    knowData->tag[j] = data[mid][j+IV_SIZE];
                }
                for(int j = 0;j<INT32_LENGTH;++j){
                    crackData->data[j] = temp[i][j+IV_SIZE+TAG_SIZE];
                    knowData->data[j] = data[mid][j+IV_SIZE+TAG_SIZE];
                }
                
                enc_int_cmp(crackData,knowData,&res);
                if(res == 0){
                    if(OutCnt<20){
                        write(std::to_string(i+1)+"->"+std::to_string(mid+1)+"\n");
                    }
                    // printf("%d->%d\n",i+1,mid+1);
                    fprintf(file,"%d\n",mid+1);
                    fflush(file);
                    break;
                }
                if(res == -1)
                    high = mid-1;
                if(res == 1)
                    low = mid+1;
            }
            if(low > high){
                if(OutCnt<20){
                    write(std::to_string(i+1)+"->Crack failed~\n");
                }
                // fprintf(file,"%d->Crack failed~\n",i+1);
                // fprintf(file,"%d\n",0);
                // fflush(file);
            }
            OutCnt++;
        }
        fclose(file);
        return true;
    } 

    // Compare in sequence, currently for the third case
    bool search(){
        int cmp_data[32];
        int cmpData,cmp_res,flag,OutCnt = 0;
        EncInt* Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
        EncInt* Know_Enc_CmpData = (EncInt*)palloc0(sizeof(EncInt));
      
        if(!ExtractAndVerify(3,5,2))
            return false;
        if(!ExtractData(3,5,cmp_data)) return false;
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
        write("CMP Data: "+std::to_string(cmp_res)+"\n");
        FILE *file;
        file = fopen("/var/lib/postgresql/14/main/crack.txt", "a"); 
        if (file == NULL) {
            printf("Unable to open the file.\n");
        }

        //start crack
        for(int i = 0 ; i < temp.size();i++){
            int res,low,high,CopyData[32];
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
                        if(OutCnt<20){
                            write(std::to_string(i+1)+"->"+std::to_string(res)+"\n");
                            OutCnt++;
                        }
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
                if(low>high){
                    fprintf(file,"%d->Crack failed\n",i+1);
                    fflush(file);
                }
            }
            else{
                if(OutCnt<20){
                    write(std::to_string(i+1)+"->"+std::to_string(cmp_res)+"\n");
                    OutCnt++;
                }
                fprintf(file,"%d\n",cmp_res);
                fflush(file);
            }
        }
        fclose(file);
        return true;
    }

    // For the fifth case, use a counter to perform the decryption
    bool Cntsearch(){
        int data[Max_N][32],NData[Max_N+5][32],temp[32],res,cmp_data,sum_data,cnt0=0,cnt1=0,bulk_size = 1,number,y;
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

       
        if(!ExtractAndVerify(5,5,2))
            return false;

       
        for (int i = 0; i < Max_N; ++i) {
            for (int j = 0; j < 32; ++j) {
                partFile >> data[i][j];
            }
        }
        partFile.close();
     
        for (int i = 0; i < Max_N; ++i) {
            for (int j = 0; j < 32; ++j) {
                NNFile >> NData[i][j];
            }
        }
        NNFile.close();
       
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

        // sub
        if(!ExtractData(5,2,temp)) return false;
        EncDataCopy(temp,Enc_SubData);

        // cmp
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

        // SUM
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
        file = fopen("/var/lib/postgresql/14/main/crack.txt", "a");
        if (file == NULL) {
            printf("Unable to open the file.\n");
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

    // For the fifth case, use a counter to perform the decryption
    bool SumSearch(){
        int temp[32],flag;
        std::vector<std::vector<int>> data(Max_N, std::vector<int>(32));
        std::vector<std::vector<int>> NData(Max_N+5, std::vector<int>(32));
        int res,cmp_data,sum_data,cnt0=0,cnt1=0,bulk_size=1,number,y,OutCnt=0;
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

        
        if(!ExtractAndVerify(5,5,2))
            return false;

        
        for (int i = 0; i < Max_N; ++i) {
            for (int j = 0; j < 32; ++j) {
                partFile >> data[i][j];
            }
        }
        partFile.close();
        
        for (int i = 0; i < Max_N; ++i) {
            for (int j = 0; j < 32; ++j) {
                NNFile >> NData[i][j];
            }
        }
        NNFile.close();
      
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

        // sub
        if(!ExtractData(5,2,temp)) return false;
        EncDataCopy(temp,Enc_SubData);

        // cmp
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

        write("CMP Data: "+std::to_string(cmp_data)+"\n");
        enc_int_sub(Enc_SubData,Enc_one,Enc_SubData_N1); //q2-1
        enc_int_sub(Enc_SubData_N1,Enc_SubData,Enc_N1); //-1

        // SUM
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

        std::ofstream("/var/lib/postgresql/14/main/crack.txt",std::ofstream::out).close();
        FILE *file;
        file = fopen("/var/lib/postgresql/14/main/crack.txt", "a");
        if (file == NULL) {
            printf("Unable to open the file.\n");
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
            if(res!=0){
                flag = res>0?1:0;
                int low = 0,high = Max_N;
                while(low <= high){
                    int mid = (low+high)/2;
                    for(int j=0;j<32;j++){
                        temp[j] = (flag==1)?data[mid][j]:NData[mid][j];
                    }
                    EncDataCopy(temp,crackData);
                    EncDataCopy2(crackData,&sum_array[bulk_size]);
                    enc_int_sum_bulk(4,sum_array,sum);
                    enc_int_cmp(Enc_CmpData,sum,&res);
                    if(res == 0){
                        res = (flag==1)?mid:(-mid);
                        res = cmp_data-res;
                        // printf("%d -> %d\n",i+1,res);
                        if(OutCnt<20){
                            write(std::to_string(i+1)+"->"+std::to_string(res)+"\n");
                            OutCnt++;
                        }
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
                if(low>high){
                    fprintf(file,"%d->Crack failed\n",i+1);
                    fflush(file);
                }
            }
            else{
                if(OutCnt<20){
                    write(std::to_string(i+1)+"->"+std::to_string(cmp_data)+"\n");
                    OutCnt++;
                }
                fprintf(file,"%d\n",cmp_data);
                fflush(file);
            }
        }
        fclose(file);
        return true;
    }

    void on_button_clicked(int filechoice) {
        std::string message;
        Gtk::FileChooserDialog dialog("Please choose a file", Gtk::FILE_CHOOSER_ACTION_OPEN);
        dialog.add_button("_Cancel", Gtk::RESPONSE_CANCEL);
        dialog.add_button("_Open", Gtk::RESPONSE_OK);

        int result = dialog.run();

        if (result == Gtk::RESPONSE_OK) {
            if(filechoice==1){
                file_path = dialog.get_filename();
                write("*********************************************Information displayed*********************************************\n");
                message = "Selected Log File: " + file_path + "\n";
                write(message);
                unset_label_background_image(label);
                file_selected = true; 
                update_confirm_button_state();
            }
            else{
                data_file_path = dialog.get_filename();
                message = "Selected Data File: " + data_file_path + "\n";
                write(message);

                data_file_selected = true; 
                update_confirm_button_state();
            }
            
        }
    }

    void on_radio_button_clicked(int number) {
        selected_radio_button = number;
        update_confirm_button_state();
    }

    void on_confirm_button_clicked() {
        confirm_button.set_sensitive(false);
        button.set_sensitive(false);
        databutton.set_sensitive(false);
        for (int i = 1; i <= 6; ++i) {
            radio_buttons[i].set_sensitive(false);
        }
        cancel_button.set_sensitive(true);
        process_file();
        std::thread([this]() {
            perform_action(selected_radio_button);
            Glib::signal_idle().connect([this]() {
                confirm_button.set_sensitive(false);
                button.set_sensitive(true);
                databutton.set_sensitive(true);
                for (int i = 1; i <= 6; ++i)  {
                    radio_buttons[i].set_sensitive(true);
                }
                cancel_button.set_sensitive(true);
                return false;
            });
        }).detach();
    }

    void process_file(){
        std::ifstream inputFile(file_path);
        if (!inputFile) {
            write("Error: Unable to open input file.");
            return ;
        }

        std::string outputFilePath = "/var/lib/postgresql/14/main/int_record_"+std::to_string(selected_radio_button)+".txt";
        std::ofstream(outputFilePath,std::ofstream::out).close();
        std::ofstream outputFile(outputFilePath);
        if (!outputFile) {
            write("Error: Unable to open output file.");
            return ;
        }

        std::string line;
        while (std::getline(inputFile, line)) {
            outputFile << line << std::endl;
        }

        inputFile.close();
        outputFile.close();
        write("Log File Copy Successfully!\n");
    }

    void on_clear_button_clicked() {
        label.set_text("");
        set_label_background_image(label);
    }

    void on_cancel_button_clicked() {
        confirm_button.set_sensitive(true);
        button.set_sensitive(true);
        databutton.set_sensitive(true);
        for (int i = 1; i <= 6; ++i) {
            radio_buttons[i].set_sensitive(true);
            radio_buttons[i].set_active(false);
        }
        file_selected = false;
        data_file_selected = false;
        selected_radio_button = -1;
        cancel_button.set_sensitive(false); 
    }

    void set_label_background_image(Gtk::Label& label) {
        Glib::RefPtr<Gtk::StyleContext> style_context = label.get_style_context();
        style_context->add_class("textview");
    }
    
    void unset_label_background_image(Gtk::Label& label) {
        Glib::RefPtr<Gtk::StyleContext> style_context = label.get_style_context();
        style_context->remove_class("textview");
    }

    void write(const std::string& text) {
        Glib::signal_idle().connect([this, text]() {
            label.set_text(label.get_text() + text);
            return false; 
        });
    }

    void update_confirm_button_state() {
        confirm_button.set_sensitive(file_selected && data_file_selected &&selected_radio_button != -1);
    }

    void perform_action(int number) {
        clock_t start = clock();
        // clock_t start,sep;
        // double elapsed;
        write("Selected CaseNum: " + std::to_string(number) + "\n Start Analyse!\n");
        switch (number) {
            case 1:
            case 2:
                write("Performing action for case "+std::to_string(number)+"\n");
                write("\n*************************************************Loading Stage*************************************************\n");
                if(!fromLog_Store()){
                    write("Log File is empty!\n");
                    break;
                }
                write("\n************************************************Preparing Stage************************************************\n");
                write("Fetching ciphertext for 1......\n");
                if(get_cipher_one(number)){
                    write("Ciphertext for 1 successfully retrieved!\n");
                }else{
                    write("Failed to retrieve ciphertext for 1, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for 2-n......\n");
                if(get_cipher_from_1_to_n(number)){
                    write("Global ciphertext retrieval successful, saved at: /var/lib/postgresql/14/main/part.txt\n");
                }else{
                    write("Global ciphertext retrieval failed, decryption unsuccessful~\n");
                    break;
                }
                write("\n*************************************************Cracking Stage*************************************************\n");
                write("Crack in progress, please wait......\n");
                if(binary_search(number)){
                    clock_t end = clock(); 
                    double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
                    write("......\nCrack file path: /var/lib/postgresql/14/main/crack.txt,Crack time:"+std::to_string(elapsed_secs)+"s\n");
                }else{
                    write("Crack failed~\n");
                }
                break;
            case 3:
                write("Performing action for case "+std::to_string(number)+"\n");
                write("\n*************************************************Loading Stage*************************************************\n");
                if(!fromLog_Store()){
                    write("Log File is empty!\n");
                    break;
                } 
                write("\n************************************************Preparing Stage************************************************\n");
                write("Fetching ciphertext for 1......\n");
                if(get_cipher_one(number)){
                    write("Ciphertext for 1 successfully retrieved!\n");
                }else{
                    write("Failed to retrieve ciphertext for 1, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for 2-n......\n");
                if(get_cipher_from_1_to_n(number)){
                    write("Global ciphertext retrieval successful, saved at: /var/lib/postgresql/14/main/part.txt\n");
                }else{
                    write("Global ciphertext retrieval failed, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for -n to 0......\n");
                if(get_cipher_from_n1_nn(number)){
                    write("Ciphertext for -n to 0 successfully retrieved, saved at: /var/lib/postgresql/14/main/part.txt\n");
                }else{
                    write("Failed to retrieve global ciphertext for -n to 0, decryption unsuccessful~\n");
                    break;
                }
                write("\n*************************************************Cracking Stage*************************************************\n");
                write("Crack in progress, please wait......\n");
                if(search()){
                    clock_t end = clock(); 
                    double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
                    write("……\nCrack file path: /var/lib/postgresql/14/main/crack.txt,Crack time:"+std::to_string(elapsed_secs)+"s\n");
                }else{
                    write("Crack failed\n");
                }
                break;
            case 4:
                write("Performing action for case "+std::to_string(number)+"\n");
                write("\n*************************************************Loading Stage*************************************************\n");
                if(!fromLog_Store()){
                    write("Log File is empty!\n");
                    break;
                }
                write("\n************************************************Preparing Stage************************************************\n");
                write("Fetching ciphertext for 1......\n");
                if(get_cipher_one(number)){
                    write("Ciphertext for 1 successfully retrieved!\n");
                }else{
                    write("Failed to retrieve ciphertext for 1, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for 2-n......\n");
                if(get_cipher_from_1_to_n_sum(number)){
                    write("Global ciphertext retrieval successful, saved at the specified path: /var/lib/postgresql/14/main/part.txt\n");
                }else{
                    write("Global ciphertext retrieval failed, decryption unsuccessful~\n");
                    break;
                }
                write("\n*************************************************Cracking Stage*************************************************\n");
                write("Crack in progress, please wait......\n");
                if(binary_search(number)){
                    clock_t end = clock(); 
                    double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
                    write("……\nCrack file path: /var/lib/postgresql/14/main/crack.txt,Crack time:"+std::to_string(elapsed_secs)+"s\n");
                }else{
                    write("Crack failed\n");
                }
                break;
            case 5:
                write("Performing action for case "+std::to_string(number)+"\n");
                write("\n*************************************************Loading Stage*************************************************\n");
                if(!fromLog_Store()){
                    write("Log File is empty!\n");
                    break;
                }
                write("\n************************************************Preparing Stage************************************************\n");
                write("Fetching ciphertext for 1......\n");
                if(get_cipher_one(number)){
                    write("Ciphertext for 1 successfully retrieved!\n");
                }else{
                    write("Failed to retrieve ciphertext for 1, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for -n to n......\n");
                if(get_cipher_from_1_to_n_sum(number)){
                    write("Ciphertext for 1 to n successfully retrieved, saved at: /var/lib/postgresql/14/main/part.txt\n");
                    write("Ciphertext for -n to 0 successfully retrieved, saved at: /var/lib/postgresql/14/main/NN.txt\n");
                }else{
                    write("Failed to retrieve global ciphertext for -n to n~\n");
                    break;
                }
                write("\n*************************************************Cracking Stage*************************************************\n");
                write("Crack in progress, please wait......\n");
                if(SumSearch()){
                    clock_t end = clock(); 
                    double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
                    write("……\nCrack file path: /var/lib/postgresql/14/main/crack.txt,Crack time:"+std::to_string(elapsed_secs)+"s\n");
                }else{
                    write("Crack failed\n");
                }
                break;
            case 6:
                write("Performing action for case "+std::to_string(number)+"\n");
                write("\n*************************************************Loading Stage*************************************************\n");
                if(!fromLog_Store()){
                    write("Log File is empty!\n");
                    break;
                }
                write("\n************************************************Preparing Stage************************************************\n");
                write("Fetching ciphertext for 1......\n");
                if(get_cipher_one(number)){
                    write("Ciphertext for 1 successfully retrieved!\n");
                }else{
                    write("Failed to retrieve ciphertext for 1, decryption unsuccessful~\n");
                    break;
                }
                write("Fetching ciphertext for 2-n......\n");
                if(get_cipher_from_1_to_n_mod()){
                    write("Global ciphertext retrieval successful, saved at the specified path: /var/lib/postgresql/14/main/part.txt\n");
                }else{
                    write("Global ciphertext retrieval failed, decryption unsuccessful~\n");
                    break;
                }
                write("\n*************************************************Cracking Stage*************************************************\n");
                write("Crack in progress, please wait......\n");
                if(binary_search(number)){
                    clock_t end = clock(); 
                    double elapsed_secs = double(end - start) / CLOCKS_PER_SEC;
                    write("……\nCrack file path: /var/lib/postgresql/14/main/crack.txt,Crack time:"+std::to_string(elapsed_secs)+"s\n");
                }else{
                    write("Crack failed\n");
                }
                break;
            default:
                write("Unknown button\n");
                break;
        }
    }


private:
    Gtk::Box vbox{Gtk::ORIENTATION_VERTICAL, 10};
    Gtk::Box hbox_files{Gtk::ORIENTATION_HORIZONTAL, 10};
    Gtk::Button button, databutton;
    Gtk::Box hbox_radio_buttons{Gtk::ORIENTATION_HORIZONTAL, 10};
    Gtk::RadioButton radio_buttons[7];
    Gtk::Button confirm_button, clear_button, cancel_button;
    Gtk::Separator separator_top, separator_middle;
    Gtk::Label label;
    Gtk::Box hbox_buttons; 
    Gtk::ScrolledWindow scrolled_window;
    std::string file_path;
    std::string data_file_path;
    bool file_selected = false; 
    bool data_file_selected = false; 
    int selected_radio_button = -1; 
};

int main(int argc, char *argv[]) {
    auto app = Gtk::Application::create(argc, argv, "org.gtkmm.example");
    MyWindow window;
    return app->run(window);
}
