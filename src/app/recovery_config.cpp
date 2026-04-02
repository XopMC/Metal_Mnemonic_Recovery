// Author: Mikhail Khoroshavin aka "XopMC"

#include "app/recovery_config.h"

#include <iostream>
#include <string>
#include <vector>

extern std::vector<std::string> derivationFiles;

bool parseDerivations(std::vector<std::string> file);

bool load_public_recovery_derivations() {
    if (derivationFiles.empty()) {
        return false;
    }

    return parseDerivations(derivationFiles);
}
