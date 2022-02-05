#include "processor.h"

#include <unistd.h>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

#include "linux_parser.h"

using std::string;
using std::vector;

// Return the aggregate CPU utilization
float Processor::Utilization() { 
    long total_jiffies_start = LinuxParser::Jiffies();
    long active_jiffies_start = LinuxParser::ActiveJiffies();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    long total_jiffies_end = LinuxParser::Jiffies();
    long active_jiffies_end = LinuxParser::ActiveJiffies();

    float delta_total = total_jiffies_end-total_jiffies_start;
    float delta_active = active_jiffies_end-active_jiffies_start;
    float cpu_utilized = delta_active/delta_total;

    return cpu_utilized;
}