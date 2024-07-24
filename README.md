![]([C:\Users\13263\Downloads\2.png](https://github.com/Krismilek/SARAs/blob/main/main/2.png))

# SARAs（Substitution and Replay Attacks）

This project is implemented based on HEDB, and we would like to thank everyone involved in the HEDB project. The concept of SARAs is to achieve cracking by replacing the parameters sent to the TEE(Trusted Execution Environment).

# Experiment Environment

-  Ubuntu 23.04
- python3.10
- GCC 11

# Install HEDB

```bash
sudo apt update
sudo apt install -y build-essential cmake libmbedtls-dev
sudo apt install -y postgresql postgresql-contrib postgresql-server-dev-all
sudo service postgresql restart
git clone -b main --depth 1 https://github.com/SJTU-IPADS/HEDB
cd HEDB
make
sudo make install
make run
```

# Install gtkmm

```bash
sudo apt update
sudo apt install libgtkmm-3.0-dev
sudo apt install pkg-config
pkg-config --cflags --libs gtkmm-3.0
```

# Run Auto SARAs

First, move main/1.css、main/2.png、main/SARAs_cmd.cpp、main/SARAs_UI.cpp to HEDB/src/integrity_zone/.

Second, cpoy main/CMakeLists.txt,then paste to HEDB/src/CMakeLists.txt and move main/c.sh to HEDB/.

Third, move test_data/private_key.pem and test_data/public_key.pem to /var/lib/postgresql/14/main.

Final, run HEDB/c.sh and run the following command.

```bash
cd HEDB && ./c.sh && ./build/attackui 2>/dev/null
```

**Note**: you can choose test_data/log/* as log file and choose test_data/test_store/* as data file.

# How can we generate the log file and data file ourselves?

- ## Generate log file

