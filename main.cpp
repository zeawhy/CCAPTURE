#include <iostream>
#include "Packetcap.h"
int main() {
    std::cout << "Hello, World!" << std::endl;
    Packetcap packetcap;
    if(!packetcap.init("enp2s0"))
        exit(0);
    if(packetcap.open()!=0)
        exit(0);
    //packetcap->setFilter();
    //while (packetcap.getNextpacket());

    while (!packetcap.getPacketloop());
    return 0;
}
