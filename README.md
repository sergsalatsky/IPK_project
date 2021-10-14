# Projekt pro předmět IPK
## Varianta ZETA: Sniffer paketů	

Autor:  Serhii Salatskyi (xsalat01)

Datum:  25 dubna 2021

## Spuštění projektu:

Program je kompatibilní s linuxovými systémy (aplikace byla testována na systémech Fedora 32 a Ubuntu 20.04). K správné kompilací je vhodné disponovat překladačů gcc 7.5.0 a vyšší.
Rovněž je potřebný program make.

V složce projektu se nachází Makefile, který umožní projekt sestavit použitím:
    
    $ make

Aplikace se spustí pomocí příkazu:

    $ sudo ./ipk-sniffer {-h} [-i rozhraní|--interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n počet}

* __-h__ (vypíše napovědu na standartní výstup [vypíše se i při zadání neplatného argumentu])
* __-i__ nebo __--interface__ <rozhraní> (právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, či bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní)
* __-p__ <port> (bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden, uvažují se všechny porty; pokud je parametr uveden, může se daný port vyskytnout jak v source, tak v destination části)
* __-t__ nebo __--tcp__ (bude zobrazovat pouze TCP pakety)
* __-u__ nebo __--udp__ (bude zobrazovat pouze UDP pakety)
* __--icmp__ (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)
* __--arp__ (bude zobrazovat pouze ARP rámce).
* __-n__ <počet> (určuje počet paketů, které se mají zobrazit; pokud není uvedeno, uvažujte zobrazení pouze jednoho paketu)
argumenty mohou být v libovolném pořadí

### Příklad spuštění

1) make
2) sudo ./ipk-sniffer -i wlp2s0 --tcp

Tento způsob provádění by otevřel rozhraní wlp2s0 pro sniffing, vytvořil výchozí filtr pouze pro TCP pakety na libovolném portu,
zachytil jeden TCP paket a výtisknul jeho obsah na standartní výstup.

Pozor:
    Program musí být spuštěn s oprávněním root. To je způsobeno tím, že tato platforma odmítne otevírací rozhraní bez oprávnění root.


Obsah archivu xsalat01.tar: Makefile, ipk-sniffer.c, README.md a manual.pdf.