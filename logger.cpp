#include "logger.h"
#include <fstream>
#include <iostream>
using namespace std;

void log_alert(const string& message) {
    ofstream logFile("nids.log", ios::app);
    if (logFile.is_open()) {
        logFile << "[ALERT] " << message << endl;
        logFile.close();
    }
    cout << "[!] ALERT: " << message << endl;
}
