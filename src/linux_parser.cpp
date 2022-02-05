#include "linux_parser.h"

#include <dirent.h>
#include <unistd.h>

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using std::stof;
using std::stoi;
using std::stol;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem()
{
    string line;
    string key;
    string value;
    std::ifstream filestream(kOSPath);
    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::replace(line.begin(), line.end(), ' ', '_');
            std::replace(line.begin(), line.end(), '=', ' ');
            std::replace(line.begin(), line.end(), '"', ' ');
            std::istringstream linestream(line);
            while (linestream >> key >> value) {
                if (key=="PRETTY_NAME") {
                    std::replace(value.begin(), value.end(), '_', ' ');
                    return value;
                }
            }
        }
    }
    return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel()
{
    string os, kernel, version;
    string line;
    std::ifstream stream(kProcDirectory+kVersionFilename);
    if (stream.is_open()) {
        std::getline(stream, line);
        std::istringstream linestream(line);
        linestream >> os >> version >> kernel;
    }
    return kernel;
}

// BONUS: Update this to use std::filesystem
/*
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}
*/
/* C17 */

// https://stackoverflow.com/a/4654718/5983691
bool is_number(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it!=s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it==s.end();
}

vector<int> LinuxParser::Pids()
{
    string value;
    vector<string> pidstr;
    vector<int> pids;

    fs::create_directories(kProcDirectory);
    for (auto& p : fs::directory_iterator(kProcDirectory)) {
        if (fs::is_directory(p)) {
            std::stringstream filename(p.path());
            while (std::getline(filename, value, '/')) {
                if (is_number(value)) pidstr.push_back(value);
            }
        }
    }
    // Convert vector<string> to vector<int>
    std::transform(pidstr.begin(), pidstr.end(), std::back_inserter(pids),
            [](const std::string& str) { return std::stoi(str); });

    return pids;
}

// Read and return the system memory utilization
float LinuxParser::MemoryUtilization()
{
    string line;
    string key;
    string value;
    float total_mem = 0.0;
    float free_mem = 0.0;

    std::ifstream filestream(kProcDirectory+kMeminfoFilename);
    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;
            if (key=="MemTotal:") total_mem = stof(value);
            if (key=="MemFree:") free_mem = stof(value);
        }
    }

    return ((float) 1-free_mem/total_mem);
}

// Read and return the system uptime
long LinuxParser::UpTime()
{
    string line;
    long uptime;

    std::ifstream filestream(kProcDirectory+kUptimeFilename);
    if (filestream.is_open()) {
        std::getline(filestream, line);
        std::istringstream linestream(line);
        linestream >> uptime;
    }

    return uptime;
}

// Read and return the number of jiffies for the system
long LinuxParser::Jiffies()
{
    long result = 0;

    vector<string> utilized = LinuxParser::CpuUtilization();
    if (!utilized.empty()) {
        for (int i = kUser_; i<=kSteal_; i++) {
            if (utilized[i]!="") result += stol(utilized[i]);
        }
    }

    return result;
}

// Read and return the number of active jiffies for a PID
long LinuxParser::ActiveJiffies(int pid)
{
    string line;
    string value;
    long result = 0;

    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatFilename);
    if (filestream.is_open()) {
        std::getline(filestream, line);
        std::istringstream linestream(line);

        // Get all time values in the pid stats file (14-17)
        // see https://man7.org/linux/man-pages/man5/proc.5.html
        int i = 0;
        while (linestream >> value) {
            if (i>=13 && i<=16) result += stol(value);
            i++;
        }
    }

    return result;
}

// Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies()
{
    return LinuxParser::Jiffies()-LinuxParser::IdleJiffies();
}

// Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies()
{
    long result = 0;

    vector<string> utilized = LinuxParser::CpuUtilization();
    if (!utilized.empty()) {
        for (int i = kIdle_; i<=kIOwait_; i++) {
            if (utilized[i]!="") result += stol(utilized[i]);
        }
    }

    return result;
}

// Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization()
{
    string line;
    string values;
    vector<string> cpu_utilization;

    std::ifstream filestream(kProcDirectory+kStatFilename);
    if (filestream.is_open()) {
        std::getline(filestream, line);
        std::istringstream linestream(line);

        while (linestream >> values) {
            // https://en.cppreference.com/w/cpp/container/vector/push_back
            if (values!="cpu") cpu_utilization.push_back(std::move(values));
        }
    }

    return cpu_utilization;
}

// Read and return the total number of processes
int LinuxParser::TotalProcesses()
{
    string line;
    string key;
    string value;
    int result;

    std::ifstream filestream(kProcDirectory+kStatFilename);
    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;
            if (key=="processes") result = stoi(value);
        }
    }

    return result;
}

// Read and return the number of running processes
int LinuxParser::RunningProcesses()
{
    string line;
    string key;
    string value;
    int result;

    std::ifstream filestream(kProcDirectory+kStatFilename);
    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;
            if (key=="procs_running") result = stoi(value);
        }
    }

    return result;
}

// Read and return the command associated with a process
string LinuxParser::Command(int pid)
{
    string value;

    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatFilename);
    if (filestream.is_open()) std::getline(filestream, value);

    return value;
}

// Read and return the memory used by a process
string LinuxParser::Ram(int pid)
{
    string line;
    string key;
    string value;
    std::stringstream memory;
    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatusFilename);

    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;

            if (key=="VmSize:")
                memory << std::fixed << std::setprecision(2) << stof(value)/1024;
        }
    }

    return memory.str();
}

// Read and return the user ID associated with a process
string LinuxParser::Uid(int pid)
{
    string line;
    string key;
    string value;
    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatusFilename);

    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::istringstream linestream(line);
            linestream >> key >> value;

            if (key=="Uid:") return value;
        }
    }

    return value;
}

// Read and return the user associated with a process
string LinuxParser::User(int pid)
{
    string line;
    string key;
    string value;
    string username;
    string uid = LinuxParser::Uid(pid);

    std::ifstream filestream(kPasswordPath);
    if (filestream.is_open()) {
        while (std::getline(filestream, line)) {
            std::replace(line.begin(), line.end(), ':', ' ');
            std::istringstream linestream(line);
            linestream >> username >> value >> key;

            if (key==uid) return username;
        }
    }

    return username;
}

// Read and return the uptime of a process
long LinuxParser::UpTime(int pid)
{
    string line;
    string value;
    vector<string> uptime;

    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatFilename);
    if (filestream.is_open()) {
        std::getline(filestream, line);
        std::istringstream linestream(line);
        while (linestream >> value) uptime.push_back(value);
    }

    if (!uptime[21].empty()) {
        return LinuxParser::UpTime()-(stol(uptime[21])/sysconf(_SC_CLK_TCK));
    }

    return 0;
}

// Read and return CPU utilization of a process
vector<string> LinuxParser::CpuUtilization(int pid)
{
    string line;
    string values;
    vector<string> cpu_utilization;

    std::ifstream filestream(kProcDirectory+to_string(pid)+kStatFilename);
    if (filestream.is_open()) {
        std::getline(filestream, line);
        std::istringstream linestream(line);

        while (linestream >> values) cpu_utilization.push_back(std::move(values));
    }

    return cpu_utilization;
}
