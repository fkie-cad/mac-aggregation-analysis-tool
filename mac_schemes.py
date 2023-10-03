from rulers import allrulers as rulers

import math

class MAC():

    def __init__(self, authenticated_pkts, len):
        self.authenticated_pkts = authenticated_pkts
        self.tag_len = len

    def get_authenticated_pkts(self):
        return self.authenticated_pkts

    def is_authenticating(self, id):
        return id in self.authenticated_pkts

class Traditional():

    name = "Trad."

    def __init__( self ):
        self.tag_length = 128

    def mac(self, pkt):

        if pkt.data_len < self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long traditional MAC into {pkt.data_len} bytes of payload!" )
            return False

        pkt.data_len -= self.tag_length
        pkt.mac_len = self.tag_length
        pkt.mac = [MAC([pkt.seq_nb], self.tag_length)]
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        return list(range(0,nb_of_dropped_packets))


# parameters
# n - number of aggregated packets
class Aggregated():

    name = "Aggregated"

    def __init__( self, n ):
        self.tag_length = 128
        self.dependencies = n
        self.name = f"Agg.({n})"

    def mac(self, pkt):

        if pkt.data_len <= self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long aggregated MAC into {pkt.data_len} bytes of payload!" )
            return False

        if pkt.seq_nb % self.dependencies == self.dependencies-1: # only add tag every *self.dependencies* packets
            pkt.data_len -= self.tag_length
            pkt.mac = [ MAC([pkt.seq_nb-x for x in range(self.dependencies)], self.tag_length)]
        else:
            pkt.mac = [ MAC([], 0)]
            
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        return list(range(0, min([self.dependencies*nb_of_dropped_packets, channel_lifetime]), self.dependencies))
        
# parameters
# n - number of aggregated packets
# o - overprovisioning factor in percent
class SlidingWindow():

    name = "Sliding Window"
    basesecurity = 128

    def __init__( self, n, o):
        self.counter = 0
        self.tag_length = math.ceil( math.ceil(128/n) * (100+o)/100)
        self.ad = n 
        self.name = f"SW({n},{o})"

    def mac(self, pkt):
        
        if pkt.data_len <= self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long aggregated MAC into {pkt.data_len} bytes of payload!" )
            return False

        pkt.data_len -= self.tag_length
        pkt.mac = [ MAC([pkt.seq_nb - x for x in range(self.ad)], self.tag_length)]
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        
        dist = 2* int(127/self.tag_length) +1
        
        return list(range(0, min([dist*nb_of_dropped_packets, channel_lifetime]), dist))

# parameters
# n - number of aggregated packets
# l - maximal loss per dropped packet
# o - overprovisioning factor in percent
class SidonSet():

    def __init__( self, n, g, o ):
        self.tag_length = math.ceil(math.ceil(128/n) * (100+o)/100)
        self.ad = n
        
        self.ruler = rulers['length-optimized'][g][self.ad][0]

        self.name = f"SS({n},{g},{o})"
        
        ### define attack strat
        # we first compute the optimal strat for an attack that does not know the bit dependency selection
        self.strat = []
        all_diffs = []
        for mark in self.ruler:
            for m in self.ruler:
                
                if mark-m in all_diffs:
                   continue
                
                # all differences in ruler that include mark
                all_diffs.append( mark - m )
            
        print(all_diffs)

        # we now have a list ('all_diffs') that contains for each ruler a number of lists with differences.
        # For the security of a message to drop to 0, at least one element (e.g. one message)
        # from each of these lists has to be dropped

        # we now look at with which dropped messages the most security loss can be generate,
        # considering that other message may already have been dropped
        
        # try to drop the 50 middle messages
        drop = [0 for i in range(50)]
            
        for i in range(1,150):
            
            
            max_count = 0
            max_message = 0
            for m in range(50,100):
                
                current_count = 0

                if m in self.strat:
                    continue
                
                for d in list(set( a-b for a in self.ruler for b in self.ruler)):
  
                    if d>=0:
                        continue
                    
                    target = m + d
                    
                    if target<50 or target >=100:
                        continue
                    
                    current_count += self.tag_length

                if current_count > max_count:
                    max_count = current_count
                    max_message = m
                    
            if max_count==0:
                break
            
            self.strat.append(max_message)
            # now we know which message is part of our strat

            for d in list(set( a-b for a in self.ruler for b in self.ruler)):
                    
                if d>=0:
                    continue
                
                target = max_message + d
                
                if target<50 or target >=100:
                    continue

                drop[target-50] += self.tag_length
                  
    
        print(self.name)
        print(drop)  
        print(self.ruler)

        self.strat = [x-50 for x in self.strat]
        
        print(self.strat)
            
        
    def mac(self, pkt):
        
        if pkt.data_len <= self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long aggregated MAC into {pkt.data_len} bytes of payload!" )
            return False
        
        pkt.data_len -= self.tag_length
        #print(self.tag_length)
        #print(self.rulers)
        
        d = []
        for j in range(self.ad):
            v = pkt.seq_nb - self.ruler[j]
            if v < 0:
                continue
            d.append(v)

        pkt.mac = [MAC( d, self.tag_length )]
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        res = []
        
        rep = 0
        index = 0
        while nb_of_dropped_packets > 0:
            cand = self.strat[index] + 50*rep
            if cand > 0 and cand not in res:
                res.append(cand)
        
            index += 1
            if index == len(self.strat):
                index = 0
                rep += 1
                
            nb_of_dropped_packets -= 1
        
        return res

# parameters
# n - number of aggregated packets
# l - maximal loss per dropped packet
# o - overprovisioning factor in percent
# d - direct authentication bits
class R2D2():

    name = "R2D2"

    def __init__( self, n, g, o):
        self.tag_length = math.ceil(math.ceil((128)/n) * (100+o)/100)
        self.ad = n
        self.g = g
        self.rulers = []
        ruler_selection = [x for x in range(self.tag_length)]

        for i in ruler_selection:
            #print(loss//self.tag_length)
            #print(self.ad)
            #print(self.tag_length)
            self.rulers.append(rulers['length-optimized'][g][self.ad][i])

        self.name = f"R2D2({n},{g},{o})"
        
        ### define attack strat
        # we compute the optimal strat for an attack that does not know the bit dependency selection
        self.strat = []

        # try to drop the 50 middle messages
        drop = [0 for i in range(50)]
            
        for i in range(49):
            
            
            max_count = 0
            max_message = 0
            max_all_count = 0
            for m in range(50,100):
                
                current_count = 0
                current_all_count = 0

                if m in self.strat:
                    continue
                
                for ruler in rulers['length-optimized'][self.g][self.ad]:
                    
                    for d in list(set( a-b for a in ruler for b in ruler)):
  
                        if d>=0:
                            continue
                    
                        target = m + d - 50
                        
                        if target<0 or target>=50:
                            continue
                                                
                        if drop[target] > 128*(o/100):
                            current_all_count += 1
                        
                        current_count += 1

                if current_count > max_count or (current_count==max_count and current_all_count>max_all_count):
                    max_count = current_count
                    max_all_count = current_all_count
                    max_message = m
            
            self.strat.append(max_message)
            # now we know which message is part of our strat

            for ruler in self.rulers:
                for d in list(set( a-b for a in ruler for b in ruler)):
                    
                    if d>=0:
                        continue
                    
                    target = max_message + d-50
                    
                    if target<0 or target >=50:
                        continue

                    drop[target] += 1
            
        self.strat = [x-50 for x in self.strat] 
        print(self.strat)
            

    def mac(self, pkt):
        
        if pkt.data_len <= self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long aggregated MAC into {pkt.data_len} bytes of payload!" )
            return False
        
        pkt.mac = []
        pkt.data_len -= self.tag_length
        #print(self.tag_length)
        #print(self.rulers)
        for i in range(self.tag_length):
            d = []
            for j in range(self.ad):
                v = pkt.seq_nb - self.rulers[i][j]
                if v < 0:
                    continue
                d.append(v)
            pkt.mac.append( MAC( d, 1 ) )
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        
        move_to_next_segment_after_x_messages = 15
        
        res = []
        
        rep = 0
        index = 0
        
        rep_index = 0
        while nb_of_dropped_packets > 0:
            
            if rep*50 < channel_lifetime:
                
                cand = self.strat[index] + 50*rep
                if cand > 0 and cand not in res:
                    res.append(cand)
            
                index += 1
                if index == move_to_next_segment_after_x_messages:
                    index = 0
                    rep += 1
                    
                nb_of_dropped_packets -= 1
            
            else:
                
                if move_to_next_segment_after_x_messages >= len(self.strat):
                    break
                
                res.append( self.strat[move_to_next_segment_after_x_messages] + 50*rep_index )
                
                rep_index += 1
                if rep_index*50 > channel_lifetime:
                    move_to_next_segment_after_x_messages += 1
                    rep_index=0
                    
                nb_of_dropped_packets -= 1
                
        
        return res


# parameters
# n - number of aggregated packets
class Compound():

    name = "Compound"

    def __init__( self, aggregated ):
        self.tag_length = math.ceil(128.0/aggregated)
        self.dependencies = aggregated
        self.name = f"Comp.({aggregated})"

    def mac(self, pkt):

        if pkt.data_len <= self.tag_length:
            print( f"Not enough space to fit {self.tag_length} byte long aggregated MAC into {pkt.data_len} bytes of payload!" )
            return False

        pkt.data_len -= self.tag_length
        start = pkt.seq_nb - self.dependencies - pkt.seq_nb%self.dependencies
        pkt.mac = [ MAC([start+x for x in range(self.dependencies)], self.tag_length)]
        return True
    
    def attack_strat( self, nb_of_dropped_packets, channel_lifetime):
        return list(range(0, min([2*self.dependencies*nb_of_dropped_packets, channel_lifetime]), 2*self.dependencies))
        