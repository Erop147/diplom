#include <stdio.h>
#include <string.h>
#include <pcap.h>

int PrintExistingDevices() {
    struct pcap_if* found_devices;
    int result;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = 0;
    result = pcap_findalldevs(&found_devices, errbuf);
    if (result < 0 || strlen(errbuf) > 0) {
        printf("Device scan error:\n%s\nMay be it need to be root?\n",errbuf);
        return -1;
    }

    while(found_devices != NULL) {
        printf("%s\n",found_devices->name);
        found_devices = found_devices->next;
    }
    return 0;
}


int main(int argc, char *argv[])
{
    PrintExistingDevices();
    return 0;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);
    return 0;
}
