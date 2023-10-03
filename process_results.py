import json
import sys
import pprint
from rulers import allrulers
import statistics

if len(sys.argv) != 3:
    print("Provide the path to a trace and the corresponding results as argument!")
    exit(0)

path = sys.argv[1]    
file = open(path, 'r')
trace = json.load(file)

path = sys.argv[2]    
file = open(path, 'r')
results = json.load(file)

schemes = results["schemes"].keys()

cutoff = 40
header_len = trace['header-size']
nb_packets = len(trace['trace'][cutoff:-cutoff])
payload_len = trace['payload-size']

#### preparations for goodput computation
nb_not_received_packets = trace['trace'][cutoff:-cutoff].count('0')
received_payload = results["sent_data"] - header_len*nb_packets - payload_len*nb_not_received_packets

#### lookup table for processing delays
processing = {'Trad.': {'avg': 238.67289225260416, 'err': 0.331868871545997}, 'Agg.(2)': {'avg': 244.64925130208334, 'err': 0.4317239906937244}, 'Agg.(4)': {'avg': 246.8744913736979, 'err': 0.48377785634532583}, 'Agg.(8)': {'avg': 248.97257486979166, 'err': 0.4870503481503559}, 'Agg.(16)': {'avg': 248.7818400065104, 'err': 0.48377785634532583}, 'Comp.(2)': {'avg': 244.26778157552084, 'err': 0.24352517407517793}, 'Comp.(4)': {'avg': 246.93806966145834, 'err': 0.4870503481503559}, 'Comp.(8)': {'avg': 248.3367919921875, 'err': 0.39050904276162834}, 'Comp.(16)': {'avg': 248.6546834309896, 'err': 0.4704603117340099}, 'SW(4,50)': {'avg': 256.8562825520833, 'err': 0.4602193204190249}, 'SW(4,100)': {'avg': 260.92529296875, 'err': 0.39050904276162834}, 'SW(8,50)': {'avg': 247.8917439778646, 'err': 0.30700457844255735}, 'SW(8,100)': {'avg': 266.83807373046875, 'err': 0.2928817820712213}, 'SW(16,100)': {'avg': 259.7808837890625, 'err': 0.39050904276162834}, 'SS(4,1,50)': {'avg': 256.2204996744792, 'err': 0.4602193204190249}, 'SS(4,1,100)': {'avg': 263.15053304036456, 'err': 0.3972308624097289}, 'SS(4,2,50)': {'avg': 257.68280029296875, 'err': 0.2928817820712213}, 'SS(8,1,50)': {'avg': 251.19781494140625, 'err': 0.44738431200497725}, 'SS(8,1,100)': {'avg': 259.2722574869792, 'err': 0.3504925923246174}, 'SS(8,2,50)': {'avg': 251.007080078125, 'err': 0.4782739473543431}, 'SS(8,2,100)': {'avg': 259.9080403645833, 'err': 0.4317239906937244}, 'R2D2(4,1,50)': {'avg': 671.7681884765625, 'err': 0.39050904276162834}, 'R2D2(4,1,100)': {'avg': 672.2768147786459, 'err': 0.4870503481503558}, 'R2D2(8,1,50)': {'avg': 711.0595703125, 'err': 0.39050904276162834}, 'R2D2(8,1,100)': {'avg': 728.3528645833334, 'err': 0.41674631944061385}, 'R2D2(8,2,50)': {'avg': 640.9327189127604, 'err': 0.17524629616230866}, 'R2D2(8,2,100)': {'avg': 761.2864176432291, 'err': 0.331868871545997}, 'R2D2(8,1,200)': {'avg': 804.9647013346354, 'err': 0.17524629616230866}}

#### lookup table for memory consumption
def spmac_memory(n,loss,o):

    bits = int(128/n * (100+o)/100)

    g = int(loss/(128/n))

    rulers = allrulers['length-optimized'][g][n][:bits]
    
    # then we add up how many bit into the past we have to track for each GR
    max = 0
    for r in rulers:
        if max < r[-1]:
            max = r[-1]
        
    # convert bits to bytes
    return (max * bits)//8

def ss_memory(n,loss,o):

    bits = int(128/n * (100+o)/100)

    g = int(loss/(128/n))

    ruler = allrulers['length-optimized'][g][n][0]

    max = ruler[-1] +1
            
    # convert bits to bytes
    return (max * bits)//8

memory = {
   'Trad.':16,
   'Agg.(2)':16*2,
   'Agg.(4)':16*4, 
   'Agg.(8)':16*8, 
   'Agg.(16)':16*16, 
   'SW(4,50)':16*4,
   'SW(4,100)':16*4,
   'SW(8,50)':16*8,
   'SW(8,100)':16*8,
   'SW(16,50)':16*16,
   'SW(16,100)':16*16,
   'SS(8,2,50)':ss_memory(8,32,50),
   'SS(8,2,100)':ss_memory(8,32,100),
   'SS(4,1,50)':ss_memory(4,32,50),
   'SS(4,1,100)':ss_memory(4,32,100),
   'SS(4,2,50)':ss_memory(4,64,50),
   'SS(4,2,100)':ss_memory(4,64,100),
   'SS(8,1,50)':ss_memory(8,16,50),
   'SS(8,1,100)':ss_memory(8,16,100),
   'R2D2(8,2,50)':spmac_memory(8,32,50),
   'R2D2(8,2,100)':spmac_memory(8,32,100),
   'R2D2(4,1,50)':spmac_memory(4,32,50),
   'R2D2(4,1,100)':spmac_memory(4,32,100),
   'R2D2(8,1,50)':spmac_memory(8,16,50),
   'R2D2(8,1,100)':spmac_memory(8,16,100),
   'R2D2(8,1,200)':spmac_memory(8,16,200),
   'Comp.(2)':16*2+16,
   'Comp.(4)':16*4+16,
   'Comp.(8)':16*8+16,
   'Comp.(16)':16*16+16 
}

output = {}

for j, scheme in enumerate(schemes):
    
        output[scheme] = {}
        


        # goodput in percent of received bytes
        output[scheme]["goodput"] = 100*results['schemes'][scheme]['goodput'] / received_payload
        if results['schemes'][scheme]["goodput"]==0:
            continue

        
        # delay
        output[scheme]["delay"] = {
            "mean": statistics.mean(results['schemes'][scheme]["delays"]) ,
            "median":statistics.median(results['schemes'][scheme]["delays"]),
            "std":statistics.pstdev(results['schemes'][scheme]["delays"]),
            "min":min(results['schemes'][scheme]["delays"]),
            "max":max(results['schemes'][scheme]["delays"])
        }
        
        # processing delay in microseconds on Zolertia Re-Mote (Cortex M3)
        output[scheme]["performance"] = processing[scheme] 
        
        # memory consumption in Byte
        output[scheme]["memory"] = memory[scheme]
        
        #resilience
        dropped_percentages = ["0", "0.2", "0.4", "0.6000000000000001", "0.8", "1.0", "2.0", "4.0", "6.0", "8.0", "10.0", "20.0", "40.0", "60.0", "80.0", "100"]
        
        output[scheme]["resilience"] = {}
        for i,x in enumerate(dropped_percentages):
            output[scheme]["resilience"][f"{i:02d}_{x}"] = results['schemes'][scheme]["attacker_capabilities"][x]
    
pprint.pprint(output)

print()
    
