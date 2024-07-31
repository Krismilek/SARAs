<div align=center>
<img src="https://github.com/Krismilek/SARAs/blob/main/main/2.png"/>
</div>

# SARAs（Substitution and Replay Attacks）

This project is implemented based on HEDB, and we would like to thank everyone involved in the HEDB project. Our code is written based on the HEDB code, but we did not modify the functional functions within HEDB. We only acted as DBAs, invoking relevant function interfaces, such as functions for interacting with the TEE and logging functions. The concept of SARAs is to achieve cracking by replacing the parameters sent to the TEE。

`record/enc_int4.cpp` adds code to record the parameters passed to the TEE in the HEDB project's `HEDB/src/integrity_zone/udf/enc_int4.cpp`. `record/record.cpp` adds digital signature code to the HEDB project's `HEDB/src/integrity_zone/record_replay/recorder.cpp`. `record/enc_int_ops.cpp` adds code to implement digital signature and HMAC functionality based on `HEDB/src/privacy_zone/enc_ops/enc_int_ops.cpp`. These three pieces of code do not modify the core functionality of the HEDB code itself.

# Experiment Environment

-  Ubuntu 23.04
- Python3.10
- gcc 11

# Install HEDB

```bash
$ sudo apt update
$ sudo apt install -y build-essential cmake libmbedtls-dev
$ sudo apt install -y postgresql postgresql-contrib postgresql-server-dev-all
$ sudo service postgresql restart
$ git clone -b main --depth 1 https://github.com/SJTU-IPADS/HEDB
$ cd HEDB
$ make
$ sudo make install
$ make run
```

# Install gtkmm

```bash
$ sudo apt update
$ sudo apt install libgtkmm-3.0-dev
$ sudo apt install pkg-config
$ pkg-config --cflags --libs gtkmm-3.0
```

# Run Auto SARAs

Firstly, move `main/1.css`、`main/2.png`、`main/SARAs_cmd.cpp`、`main/SARAs_UI.cpp` to `HEDB/src/integrity_zone/`.

Secondly, copy `main/CMakeLists.txt`,then paste to `HEDB/src/CMakeLists.txt` and move `main/c.sh` to `HEDB/`.

Thirdly, move `test_data/private_key.pem` and `test_data/public_key.pem` to `/var/lib/postgresql/14/main`.

Finally, run `HEDB/c.sh` and run the following command.

```bash
$ cd HEDB && ./c.sh && ./build/attackui 2>/dev/null
```

**Note**: you can choose `test_data/log/*` as log file and choose `test_data/test_store/*` as data file.

# How can we generate the log file and data file ourselves?

- ## Generate log file

Firstly, copy `record/recorder.cpp` ,then paste to `HEDB/src/integrity_zone/record_replay/recorder.cpp`.

Secondly, comment out all the code in `HEDB/src/integrity_zone/record_replay/replay.cpp`. 

Thirdly, modify line 25 in `HEDB/src/integrity_zone/interface/interface.cpp` to `true`, then comment out lines 92 to 105.

Finally,recompile and link HEDB again, send SQL to PostgreSQL, then you can find related log file in `/var/lib/postgresql/14/main`.

```bash
$ cd HEDB && ./c.sh
```

- ## Generate data file

Firstly, copy `record/enc_int4.cpp` ,then paste to `HEDB/src/integrity_zone/udf/enc_int4.cpp`.

Secondly, recompile and link HEDB again, send SQL  which contain **PLUS**  operator to PostgreSQL, then you can find related data file in `/var/lib/postgresql/14/main`.

```bash
$ cd HEDB && ./c.sh
```

**Note**: to avoid generating too many log files, you can change line 25 in `HEDB/src/integrity_zone/interface/interface.cpp` to `false`.

# How to perform SARAs on TPC-DS?

TPC-DS is a benchmark for decision support systems that models several common aspects of decision support, including queries and data maintenance. It is used to measure the analytical performance of big data products.

For more usage instructions, see `tpcds/README.md`.

# How to Simulate Digital Signatures and HMAC？

Our experiment uses RSA signatures. To simplify the experiment, a 512-bit key is used, and the generated signature is stored in base64 encoding. For HMAC, a random 512-bit key is generated, and the hash function used is sha512. How to use it? Firstly, copy `record/enc_int_ops.cpp`, then paste to `HEDB/src/privacy_zone/enc_ops/enc_int_ops.cpp`. Finally, recompile the HEDB project.

**Note**: Please modify the file paths involved in the code as needed.
