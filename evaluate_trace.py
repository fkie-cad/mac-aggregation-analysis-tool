import pprint
import os
import json
import glob
import sys

from mac_schemes import Traditional, Aggregated, SlidingWindow, R2D2, SidonSet, Compound

mac_schemes = [
        Traditional(),
        
        Aggregated(2),
        #Aggregated(4),
        #Aggregated(8),
        #Aggregated(16),
        
        Compound(2),
        Compound(4),
        #Compound(8),
        #Compound(16)
        
        #SlidingWindow(4,50),
        #SlidingWindow(4,100),
        #SlidingWindow(8,50),
        #SlidingWindow(8,100),
        #SlidingWindow(16,100),

        #SidonSet(4,1,50),
        #SidonSet(4,1,100),
        #SidonSet(4,2,50),
        #SidonSet(4,2,100),
        #SidonSet(8,1,50),
        #SidonSet(8,1,100),
        #SidonSet(8,2,50),
        #SidonSet(8,2,100),

        #R2D2(4,1,50),
        #R2D2(4,1,100),
        #R2D2(8,1,50),
        #R2D2(8,1,100),
        #R2D2(8,1,200),
        #R2D2(8,2,50),
        #R2D2(8,2,100),

        
    ] # 128 bit security ,

class Packet():

    def __init__(self, length, seq_nb):

        self.data_len = length
        self.mac_len = 0
        self.seq_nb = seq_nb


if __name__ == "__main__":
    
    if len(sys.argv) != 2:
        print("Provide the path to a trace as argument!")
        
    path = sys.argv[1]    
    file = open(path, 'r')
    trace = json.load(file)
    
    cutoff = 40 # how old can a packet be before we give up on it ever being fully authenticated? For the predefined parameters, all message that can be authenticated will be done so after less than 40 packets
    
    results = {}

    channel_lifetime = len(trace['trace'])

    results['name'] = trace['name']
    results['sent_data'] = (channel_lifetime-2*cutoff)*(trace['payload-size'] + trace['header-size']) 
    results['schemes'] = {}

    for scheme in mac_schemes:
        
        error_rate = []
        
        goodput = 0
        received_pkts = {}
        unprocessed_macs = []
        
        delays = []

        for seq_nb in range(channel_lifetime):

            pkt = Packet( trace['payload-size'], seq_nb )
            if scheme.mac(pkt) == False:
                continue

            if trace['trace'][seq_nb] == '0' : # pkt was not received
                continue

            # pkt was received
            received_pkts[pkt.seq_nb] = {'len': pkt.data_len, 'auth': 0} # packet has no authentication yet
            unprocessed_macs += pkt.mac

            to_remove = []
            for mac in unprocessed_macs:
                for p in mac.get_authenticated_pkts():
                    if pkt.seq_nb - p > cutoff:
                        to_remove.append(mac)
                        break
                    if not p in received_pkts: # one of the packets necessary to verify this MAC has not been received
                        break
                else:
                    
                    for p in mac.get_authenticated_pkts():
                        received_pkts[p]['auth'] += mac.tag_len
                        if received_pkts[p]['auth']>=128 and received_pkts[p]['auth']-mac.tag_len<128:
                            delays.append( seq_nb - p )
                        
                    to_remove.append(mac)

            for mac in to_remove:
                unprocessed_macs.remove(mac)
        
        for p in received_pkts:
            
            if (p < cutoff) or (p > channel_lifetime - cutoff-1):
                continue

            #print("test")

            if received_pkts[p]['auth'] >= 128: # 128 bit security
                goodput += received_pkts[p]['len']

        results['schemes'][scheme.name] = {'goodput':goodput, 'delays':delays}
            



base = [x*.5 for x in range(1,20)]
factors = [.1,1,10]
temp = [(x, y) for x in base for y in factors]
# how many of all packets can be selectively dropped by an attacker
dropped_percentages = [ x[0]*x[1] for x in temp ]
dropped_percentages.append(0)
dropped_percentages.append(100)

attacker_capabilities = {}
for x in dropped_percentages:
    attacker_capabilities[x] = int(x/100*(channel_lifetime-2*cutoff))
    

 

for scheme in mac_schemes:
    
    results['schemes'][scheme.name]['attacker_capabilities'] = {}
    
    for key in attacker_capabilities:
                
        nb_of_dropped_packets = attacker_capabilities[key]
        
        attacked_seq_nbs = scheme.attack_strat( nb_of_dropped_packets, channel_lifetime-2*cutoff)
        
        # compensate for warm up phase during evaluation
        attacked_seq_nbs = [ x+cutoff for x in attacked_seq_nbs ]
        attacked_seq_nbs = set(attacked_seq_nbs)
    
        error_rate = []
        
        goodput = 0
        received_pkts = {}
        unprocessed_macs = []
        
        for seq_nb in range(channel_lifetime):
            
            pkt = Packet( trace['payload-size'], seq_nb )
            if scheme.mac(pkt) == False:
                continue

            if trace['trace'][seq_nb] == '0' or seq_nb in attacked_seq_nbs : # pkt was not received
                continue

            # pkt was received
            received_pkts[pkt.seq_nb] = {'len': pkt.data_len, 'auth': 0} # packet has no authentication yet
            unprocessed_macs += pkt.mac

            to_remove = []
            for mac in unprocessed_macs:
                for p in mac.get_authenticated_pkts():
                    if pkt.seq_nb - p > cutoff:
                        to_remove.append(mac)
                        break
                    if not p in received_pkts: # one of the packets necessary to verify this MAC has not been received
                        break
                else:
                    
                    for p in mac.get_authenticated_pkts():
                        received_pkts[p]['auth'] += mac.tag_len
                        
                    to_remove.append(mac)

            for mac in to_remove:
                unprocessed_macs.remove(mac)
        
        for p in received_pkts:
            
            if (p < cutoff) or (p > channel_lifetime - cutoff-1):
                continue

            #print("test")

            if received_pkts[p]['auth'] >= 128: # 128 bit security
                goodput += received_pkts[p]['len']

        results['schemes'][scheme.name]['attacker_capabilities'][key]=goodput

print(results)
     
# delete file content
open(f'results/{trace["name"]}.results', 'w').close()    
    
with open(f'results/{trace["name"]}.results', 'w', encoding='utf-8') as f:  
    json.dump(results, f, indent=4)