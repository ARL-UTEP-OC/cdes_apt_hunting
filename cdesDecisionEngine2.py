#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import time
import sys
import random
import os
import logging
#Required import
from Trigger.trigger import Trigger

#Required class name that inherits Trigger
class MyTrigger(Trigger):  
    
    #Required function
    def process_data(self):

        #change it per cdes node
        cur_decision_point = 1

        nodes = self.get_cc_node_numbers()
        
        
        
        cdes1_hpmap = {"jboss": nodes[0], "warftp": nodes[1], "ssh": nodes[2]} 
        cdes2_hpmap = {"warftp": nodes[0], "jboss": nodes[1], "webserver_db": nodes[2]}
        
        
        attackers = {0: 0, 1: 1} 
        att_exploits = {}
        att_exploits[0] = {1: 'jboss', 2: 'webserver_db', 3: 'ssh'}
        att_exploits[1] = {1: 'warftp', 2: 'ssh', 3: 'webserver_db'}
        
        att_preference = {}
        att_preference[0] = {'jboss': 1, 'webserver_db': 2, 'ssh': 2}
        att_preference[1] = {'warftp': 1, 'ssh': 2, 'webserver_db': 2}
        
        #hp options
        honeypots = {}
        honeypots[0] = {1: 'warftp', 2: 'ssh', 3: 'jboss'}
        honeypots[1] = {1: 'warftp', 2: 'jboss', 3: 'webserver_db'}
        
        
        #success history of hp options
        hp_success_hist = {}
        hp_success_hist = {'warftp': 0, 'ssh': 0, 'jboss': 0, 'webserver_db': 0}
        
        
        
        #legit nodes
        legit_nodes = {}
        legit_nodes[0] = {1: 'ssh'}
        legit_nodes[1] = {1: 'webserver_db'}
        
        
        isdecision_made = {0: False, 1: False}
        #create a decsion point file for logging
        
#        f = open("/tmp/active_cdes.hist","w+")
#        f.write("activate cdes : 1"+"\n")
#        f.close()
#        
#        f = open("/tmp/hp_success.hist","w+")
#        f.write(str(hp_success_hist)+"\n")
#        f.close()
        
        
        
        
        activated_hp = {0: "", 1: ""}
        
        cdes_alert_count = {"legit":0, "legit2":0, "honey1":0, "honey2":0}
        
       
        
        
        #forever loop to process data
        
#        prevtime = datetime.datetime.now()
        
        while True:
            
#            curtime = datetime.datetime.now()
            signal = "" # legit or honey
            #logging.debug("signal******CDES2***signal*******************"+ str(signal))
#            if curtime.second - prevtime.second > 5:
#                
#                prevtime = curtime
            signal = self.checkForSignal()
            
            if "activate cdes : 1" in signal and isdecision_made[cur_decision_point]==False and cur_decision_point == 0:
                # activate the second decision point
                #logging.debug("signal******CDES2***signal*******************"+ str(signal))
                hp = self.make_decision(attackers, att_exploits, att_preference, honeypots[cur_decision_point], hp_success_hist, legit_nodes[cur_decision_point])
                self.set_active_conn(cdes1_hpmap[hp])
                isdecision_made[cur_decision_point] = True
                self.updateCdesHist("cdes 1 activated "+ str(hp))
                activated_hp[cur_decision_point] = hp
            
            if "activate cdes : 2" in signal  and isdecision_made[cur_decision_point]==False and cur_decision_point == 1:
                #logging.debug("signal******CDES2***signal*******************"+ str(signal))
                # activate the second decision point
                hp = self.make_decision(attackers, att_exploits, att_preference, honeypots[cur_decision_point], hp_success_hist, legit_nodes[cur_decision_point])
                self.set_active_conn(cdes2_hpmap[hp])
                isdecision_made[cur_decision_point] = True
                self.updateCdesHist("cdes 2 activated "+ str(hp))
                activated_hp[cur_decision_point] = hp
                
           
            
            
            #check the alerts
            #it contains the position of the attacker
            #determine whether he is in legit or honeypot
            #logging.debug("Outside*****CDES2****isdecision_made[cur_decision_point]**"+ str(isdecision_made[cur_decision_point]))
            #logging.debug("Outside******CDES2***cur_decision_point**"+ str(cur_decision_point))
            




            data = self.read_input_line()
            #if data yet exists, restart loop
            
            if data == None:
                #logging.debug("*****************NO DATA*********************")
                continue
            
	    
            #logging.debug("READ: " + str(data))
            #logging.debug("$$$$$$$$$$$$$$$And there was data $$$$$$$$$$")
            line = str(data)



            
            if "Legit" in line or "Honey" in line:
                #print("attacker attacked legit network")
                #legit, which node, which exploit
                legitorhoney, exploit, node, name = self.parseAttackAlert(line)
                #logging.debug("Inside******CDES2***legitorhoney**"+ str(legitorhoney))
                #logging.debug("Inside******CDES2***exploit**"+ str(exploit))
                #logging.debug("Inside******CDES2***node**"+ str(node))
                
                cdes_alert_count[legitorhoney.lower()] = cdes_alert_count[legitorhoney.lower()] + 1
                
                if "legit" in legitorhoney.lower() and cdes_alert_count[legitorhoney.lower()] == 1 and  isdecision_made[cur_decision_point] == True and cur_decision_point == 0:
                    logging.debug("Inside******CDES1***legitorhoney**"+ str(legitorhoney))
                    logging.debug("Legit1*****CDES1****isdecision_made[cur_decision_point]**"+ str(isdecision_made[cur_decision_point]))
                    logging.debug("Legit1*****CDES1***cur_decision_point**"+ str(cur_decision_point))
                    #cur_decision_point = cur_decision_point + 1
                    self.updateCdesHist("attacker avoided Honey1 "+name + ":"+node+ "; activate cdes : 2")
                    hp_success_hist[activated_hp[cur_decision_point]] = hp_success_hist[activated_hp[cur_decision_point]] - 1
                    self.updateHpHist(hp_success_hist, "write")
                elif "honey1" in legitorhoney.lower() and cdes_alert_count[legitorhoney.lower()] == 1 and isdecision_made[cur_decision_point] == True and cur_decision_point == 0:
                    logging.debug("Inside******CDES1***legitorhoney**"+ str(legitorhoney))
                    logging.debug("Honey1*****CDES1****isdecision_made[cur_decision_point]**"+ str(isdecision_made[cur_decision_point]))
                    logging.debug("Honey1*****CDES1***cur_decision_point**"+ str(cur_decision_point))
                    #cur_decision_point = cur_decision_point + 1
                    self.updateCdesHist("attacker got caught in Honey1 "+name + ":"+node)
                    hp_success_hist[activated_hp[cur_decision_point]] = hp_success_hist[activated_hp[cur_decision_point]] + 1
                    self.updateHpHist(hp_success_hist)
                
                if "legit2" in legitorhoney.lower() and cdes_alert_count[legitorhoney.lower()] == 1 and isdecision_made[cur_decision_point] == True and cur_decision_point == 1:
                    #cur_decision_point = cur_decision_point + 1
                    logging.debug("Inside******CDES2***legitorhoney**"+ str(legitorhoney))
                    logging.debug("Legit2*****CDES2****isdecision_made[cur_decision_point]**"+ str(isdecision_made[cur_decision_point]))
                    logging.debug("Legit2*****CDES2***cur_decision_point**"+ str(cur_decision_point))
                    self.updateCdesHist("Attacker reached goal "+name + ":"+node)
                    hp_success_hist[activated_hp[cur_decision_point]] = hp_success_hist[activated_hp[cur_decision_point]] - 1
                    self.updateHpHist(hp_success_hist, "write")
                elif "honey2" in legitorhoney.lower() and cdes_alert_count[legitorhoney.lower()] == 1 and isdecision_made[cur_decision_point] == True and cur_decision_point == 1:
                    logging.debug("Inside******CDES2***legitorhoney**"+ str(legitorhoney))
                    logging.debug("Honey2*****CDES2****isdecision_made[cur_decision_point]**"+ str(isdecision_made[cur_decision_point]))
                    logging.debug("Honey2*****CDES2***cur_decision_point**"+ str(cur_decision_point))
                    #cur_decision_point = cur_decision_point + 1
                    self.updateCdesHist("attacker got caught in Honey2 "+name + ":"+node)
                    hp_success_hist[activated_hp[cur_decision_point]] = hp_success_hist[activated_hp[cur_decision_point]] + 1
                    self.updateHpHist(hp_success_hist, "write")
                    
                    
                    
            
            
            
            
            
            #if he is in legit network
            #then update the decision point to next level
            #update the algo_cdes1.hist file
            #update the hp_success_hist file
            #update hp_success_hist
            #so that the 2nd cdes node can make the decision
            
            
            ####
    def updateCdesHist(self, msg):
        
        f = open("/tmp/active_cdes.hist","a+")
        f.write(msg+"\n")
        f.close()
        
    
    
    def parseAttackAlert(self, alert):
        
        #Legit-Manual SSH Connection to 10.0.4.2
        #Legit-Metasploit sshexec Connection to 10.0.4.2
        
        
        #Honey1-JBOSS JMX_INVOKER Exploit to 10.0.6.2
        
        #Honey-Manual SSH Connection to 10.0.10.10
        
        #Honey1-USER SUBMIT EXPLOIT to 10.0.23.10 CMD
        #Honey1-FTP Connection Banner from 10.0.23.10
        
        #Legit-SQLMAP SQLInjection username field against Webserver w Database 10.0.14.100
        
        #Honey2-JBOSS JMX_INVOKER Exploit to 10.0.12.2
        
        #Honey2-USER SUBMIT EXPLOIT to 10.0.16.10
        #Honey2-FTP Connection Banner from 10.0.16.10
        
        #Honey2-SQLMAP SQLInjection username field against Webserver w Database 10.0.11.100
        
        legitorhoney =""
        node = ""
        exploit = ""
        name = ""
        
        if "Legit" in alert and "10.0.4.2" in alert:
            legitorhoney = "Legit"
            if "Manual SSH" in alert:
                exploit = "Manual SSH"
            if "10.0.4.2" in alert:
                node = "10.0.4.2"
            name = "ssh"
        
        
        if "Honey1" in alert:
            legitorhoney = "Honey1"
            if "Manual SSH" in alert:
                exploit = "Manual SSH"
                node = "10.0.10.10"
                name = "ssh"
            elif "JBOSS" in alert:
                exploit = "JBOSS"
                node = "10.0.6.2"
                name = "jboss"
            elif "FTP Connection Banner" in alert or "USER SUBMIT EXPLOIT to 10.0.23.10":
                exploit = "Warftp"
                node = "10.0.23.10"
                name = "warftp"
                
                
        if "Legit" in alert and "10.0.14.100" in alert:
            legitorhoney = "Legit2"
            if "Legit-SQLMAP SQLInjection" in alert:
                exploit = "SQLMAP SQLInjection"
            if "10.0.14.100" in alert:
                node = "10.0.14.100"
            name = "webserver_db"
            
            
        if "Honey2" in alert:
            legitorhoney = "Honey2"
            if "SQLMAP SQLInjection" in alert:
                exploit = "SQLMAP SQLInjection"
                node = "10.0.11.100"
                name = "webserver_db"
            elif "JBOSS JMX_INVOKER Exploit" in alert:
                exploit = "JBOSS JMX_INVOKER Exploit"
                node = "10.0.12.2"
                name = "jboss"
            elif "FTP Connection Banner" in alert or "USER SUBMIT EXPLOIT to 10.0.16.10" in alert:
                exploit = "Warftp"
                node = "10.0.16.10"
                name = "warftp"
            
        
        return legitorhoney, exploit, node, name;
                
                
        
            
            
        
            
        
        
    
    def checkForSignal(self):
        
        
        file = "/tmp/active_cdes.hist"
            #hp_success_hist = f.read()
         
        f = open(file,"r")
        f1 = f.readlines()
        last_line = "None"
        for x in f1:
            last_line = x
        #print(last_line)
        
        signal = last_line
        
        return signal 
        
        

    def updateHpHist(self, hp_success_hist, operation):
        
        if operation == "read":
            file = "/tmp/hp_success.hist"
            #hp_success_hist = f.read()
            
            f = open(file,"r")
            f1 = f.readlines()
            last_line = "None"
            for x in f1:
                last_line = x
            #print(last_line)
            
            str1 = last_line[1:-2]
            
            keyval = str1.split(',')
            hp_success_hist = {}
            for tok in keyval:
                
                kv = tok.split(':')
                key = kv[0].strip()
                key = key[1:-1]
                val = int(kv[1].strip())
                #print(key +"->" +val)
                hp_success_hist[key] = val
        else:
            f = open("/tmp/hp_success.hist","a+")
            f.write(str(hp_success_hist)+"\n")
            f.close()
        
        return hp_success_hist;

        
    
        

    def make_decision(self,attackers, att_exploits, att_preference, honeypots, hp_success_hist, legit_nodes):
        
        overlaps = {}
        actions = {}
        
        #update the hp_success_hist
        hp_success_hist = self.updateHpHist(hp_success_hist, "read")
        
        for i in honeypots:
            #we can choose one or multiple hp
            cur_hp = {}
            cur_hp[honeypots[i]] = honeypots[i]
            #print("Hp options: ")
            #print(honeypots[i])
            # for each attacker find the attack nodes: hp or legit node
            attack_plan = self.computeAttackPlan(attackers, cur_hp, legit_nodes, att_exploits, att_preference)
            # choose the action from the plan for each of the attackers
            #Then compute the overlapping length of the attacks
            chosen_attack = self.chosenAttack(attack_plan)
            #this method also resolves tie
            olap, node1, node2 = self.computeOverlap(chosen_attack)
            overlaps[honeypots[i]] = olap
            actions[honeypots[i]] = [node1, node2]
            #print("\n")
        #print("overlaps for HPs: ", overlaps)
        
        #print(actions)
        #now choose which hp to deploy based on history and current overlaps
        hptodeploy = self.findOptimalHP(overlaps, hp_success_hist)
        #print("defender deploys HP *******:", hptodeploy)
        return hptodeploy    
    
    
    
    
    def findOptimalHP(self, overlaps, hp_success_hist):
        
        #find optimal overlap and action
        optimal_hp = {}
        minHP = min(overlaps.keys(), key=(lambda k: overlaps[k]))
    #    print("MinHP:")
    #    print(minHP)
        minoverlap = overlaps[minHP]
        #find duplicates
        for hp in overlaps:
            if overlaps[hp] == minoverlap:
                optimal_hp[hp] = overlaps[hp]
                
        #print("optimal HPs: ", optimal_hp)
        
        
        if len(optimal_hp) > 1:
            for hp in optimal_hp:
                optimal_hp[hp] = optimal_hp[hp] - hp_success_hist[hp]
        
        
        
#        print("weights: ", hp_success_hist)
#        print("weighted overlap: ", optimal_hp)
        
       
        
        optHP = min(optimal_hp.keys(), key=(lambda k: optimal_hp[k]))
        
        
        minoverlap = optimal_hp[optHP]
        
        finalHPs = {}
        
        for hp in optimal_hp:
            if optimal_hp[hp] == minoverlap:
                finalHPs[hp] = optimal_hp[hp]
        
        
        finalHP = random.choice(list(finalHPs.keys()))
        return finalHP
            
        
            
        
    
    
    def chosenAttack(self, attack_plan):
    
        chosen_attack = {}
        chosen_attack[0] = []
        chosen_attack[1] = []
        for at in attack_plan:
            cur_prio= sys.maxsize
            for hp in attack_plan[at]:
                if attack_plan[at][hp] < cur_prio:
                    cur_prio = attack_plan[at][hp]
                    chosen_attack[at] = []
                    chosen_attack[at].append(hp)
                elif attack_plan[at][hp] == cur_prio:
                    chosen_attack[at].append(hp)
                        
                        
#        print("Chosen action")
#        print(chosen_attack)
        return chosen_attack
       
        
    def computeAttackPlan(self, attackers, cur_hp, legit_nodes, att_exploits, att_preference):
        attack_plan = {}
        attack_plan[0] = {}
        attack_plan[1] = {}
        for att in attackers:
            for hp in cur_hp:
                if hp in att_exploits[att].values():
                    attack_plan[att][hp] = att_preference[att][hp]
                else:
                    attack_plan[att][hp] = sys.maxsize
                
                for ln in legit_nodes.values():
                    if ln in att_exploits[att].values():
                        attack_plan[att][ln] = att_preference[att][ln]
                    else:
                        attack_plan[att][ln] = sys.maxsize
            
#        print("Attack Plan")
#        print(attack_plan)
        return attack_plan
        
    
    def computeOverlap(self, chosen_attack):
        #print("here I am in computeoverlap")
        
        
        node1 = ""
        node2 = ""
        max_overlap = -1
        for att1 in chosen_attack:
            for att2 in chosen_attack:
                if att1 != att2:
                    for a1 in chosen_attack[att1]:
                        for a2 in chosen_attack[att2]:
                            if a1 == a2:
                                if max_overlap < 1:
                                    max_overlap = 1
                                    node1 = a1
                                    node2 = a2
                            elif a1 != a2:
                                if max_overlap < 0:
                                    max_overlap = 0
                                    node1 = a1
                                    node2 = a2
        return max_overlap, node1, node2;
    
    

