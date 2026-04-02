// Author: Mikhail Khoroshavin aka "XopMC"

#pragma once

extern bool g_public_help_requested;

bool is_public_recovery_flag(const char* arg);
bool is_supported_public_target_family(char value);

void printHelp();
