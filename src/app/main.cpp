// Author: Mikhail Khoroshavin aka "XopMC"

#include "app/recovery_app.h"

// main: thin public entry point that delegates into the recovery app.
int main(int argc, char** argv) {
    return RunRecoveryApp(argc, argv);
}
