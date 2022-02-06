#include <unistd.h>
#include <cctype>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>

#include "process.h"
#include "linux_parser.h"

using std::string;
using std::to_string;
using std::vector;
using std::stol;

// Return this process's ID
int Process::Pid() { return pid_; }

// Return this process's CPU utilization
// https://stackoverflow.com/a/16736599/5983691
float Process::CpuUtilization()
{
    long uptime = LinuxParser::UpTime();

    // #14 utime - CPU time spent in user code, measured in clock ticks
    // #15 stime - CPU time spent in kernel code, measured in clock ticks
    // #16 cutime - Waited-for children's CPU time spent in user code (in clock
    // ticks) #17 cstime - Waited-for children's CPU time spent in kernel code (in
    // clock ticks) #22 starttime - Time when the process started, measured in
    // clock ticks
    vector <string> cpu_utilization = LinuxParser::CpuUtilization(pid_);
    long utime = stol(cpu_utilization[13]);
    long stime = stol(cpu_utilization[14]);
    long cutime = stol(cpu_utilization[15]);
    long cstime = stol(cpu_utilization[16]);
    long start_time = stol(cpu_utilization[21]);

    // First we determine the total time spent for the process:
    long total_time = utime+stime;

    // We also have to decide whether we want to include the time from children
    // processes. If we do, then we add those values to total_time:
    total_time = total_time+cutime+cstime;

    // Next we get the total elapsed time in seconds since the process started:
    float seconds = uptime-(start_time/sysconf(_SC_CLK_TCK));

    // Finally we calculate the CPU usage percentage:
    float cpu_usage = ((total_time/sysconf(_SC_CLK_TCK))/seconds);

    return cpu_usage;
}

// Return the command that generated this process
string Process::Command() { return LinuxParser::Command(pid_); }

//Return this process's memory utilization
string Process::Ram() { return LinuxParser::Ram(pid_); }

// Return the user (name) that generated this process
string Process::User() { return LinuxParser::User(pid_); }

//Return the age of this process (in seconds)
long int Process::UpTime() { return LinuxParser::UpTime(pid_); }

// Overload the "less than" comparison operator for Process objects
bool Process::operator<(Process& a) {
  return Process::CpuUtilization()<a.Process::CpuUtilization();
}