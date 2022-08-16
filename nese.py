# -*- coding: utf-8 -*-
import base64,urllib3,json,threading,sys,time,random,string,collections,zlib
import socket
import importlib
urllib3.disable_warnings()
import grpc
import helloworld_pb2 as pb
import helloworld_pb2_grpc as func
from functools import partial
# import helloworld_pb2 as helloworld__pb2
datahash=''
import sys
importlib.reload(sys)
# sys.setdefaultencoding('utf8')
class Storage:
    def __init__(self):
        self.contentsB = ''
        self.contentsH = {}
    def storeBody(self, buf):
        self.contentsB+=buf
    def storeHeader(self, buf):
        if ': ' in buf:
            a= buf.split(': ',1)
            if a[0] in self.contentsH:
                self.contentsH[a[0]]+=a[1]
            else:
                self.contentsH[a[0]]=a[1]
        # print buf
    def loadBody(self):
        return self.contentsB
    def loadHeader(self):
        return self.contentsH
class reqfuncmjzj:
    printlog=1
    printlogreq=1
    printlogres=1
    gold=0
    playername=''.join(random.sample('zyxwvutsrqponmlkjihgfedcbaABCDEFGHIJKLMNOPQRSTUVWXYZ',4))
    yjm=''
    password='qqqqqqqq'
    ClientVersion = '1.0.0'
    loginData={}
    my_slist=[]
    sessionKey_=''
    meta={
'x-apb-app-version': '1.3.38',
'x-apb-language': 'ChineseTraditional',
'x-game-id': '2',
'x-apb-os-version': 'iOS 14.3',
'x-apb-device-name': 'iPhone12,5',
'x-apb-platform-type-id': '91',
'x-apb-os-type': '1',
'x-apb-platform-type': '1',
# 'x-apb-request-datetime': '1657778075',
'x-apb-request-id': '626423703422566917',
'x-sns-user-id': '1547422664945041408',
'x-apb-user-id': '1000000000000052521',
'x-apb-session-key': '',
'x-apb-token': '',
'x-apb-master-data-hash': '',
'x-apb-device-id': 'AF06EC04-1EBB-433A-BAC3-48D359B2C106',
'x-apb-advertising-id': '00000000-0000-0000-0000-000000000000',
'x-apb-keychain-user-id': '1000000000000052521',

    }
    def initHeaders(self):
        iphone_type=["iPhone7,2","iPhone8,1","iPhone8,2","iPhone9,4","iPhone9,2","iPhone9,3","iPhone9,1","iPhone10,1","iPhone10,4","iPhone10,2","iPhone10,5","iPhone10,3","iPhone10,6","iPhone8,4","iPad4,8","iPad5,1","iPad5,2","iPad5,3","iPad5,4","iPad6,3","iPad6,4","iPad6,7","iPad6,8","iPad6,11","iPad6,12","iPad7,1","iPad7,2","iPad7,3","iPad7,4"]
        ios_type=["10.0.1","10.3.2","10.3.3","9.0.2","9.3.1","9.3.2","11.0.1","11.0.2","11.3.1","11.4","11.4.1","12.0"]
        self.req_id=1
        self.device_name = random.sample(iphone_type,1)[0]
        self.operating_system = random.sample(ios_type,1)[0]
    def hmac_sha256(self,message,auth_key):
        import hmac,hashlib
        return base64.b64encode(hmac.new(auth_key, message, digestmod=hashlib.sha256).digest())
    def gensha1(self,data):
        import hashlib
        # print 'gensha1',data
        m2 = hashlib.sha1()
        m2.update(data.encode('utf-8'))
        return bytes(m2.hexdigest(),'utf-8')
    def des_ecb_dec(self,data,key):
        from Crypto.Cipher import DES
        des = DES.new(key, DES.MODE_ECB)
        decrypt_data = des.decrypt(data)
        return self.unpad(decrypt_data)
    def des_ecb_enc(self,data,key):
        from Crypto.Cipher import DES
        des = DES.new(key, DES.MODE_ECB)
        encrypt_data = des.encrypt(self.pad8(data))
        return (encrypt_data)
    def pad8(self,k):
        if 8 > len(k):
            padding = 8 - len(k)
            k = k + chr(padding).encode('utf-8')*padding
        elif 8 < len(k):
            padding = 8 - (len(k)%8)
            k = k + chr(padding).encode('utf-8') * padding
        else:
            k = k + chr(8).encode('utf-8') * 8
        return k
    def aa(self):
        orijson=json.loads(open('battlerecord/config').read())
        # print(orijson)
        newjson=json.loads(open('battlerecord/configwithstam').read())
        for obj in orijson:
            # print(obj)
            if obj not in newjson:
                newjson[obj]=orijson[obj]
        open('battlerecord/configwithstam','w').write(json.dumps(newjson))
        return
        # a=open('battlereq/za21_52','rb').read()
        # print(a)
        # aaa=pb.StartEventQuest()
        # aaa.ParseFromString(a)
        # print(aaa)
        # return
            
        da='08ba85061084dc061804'
        da=bytes.fromhex(da)
        # print da.encode('hex')
        # da=open('battlereq/111').read()
        # print da.encode('hex')

        aaa=pb.StartEventQuest()
        aaa.ParseFromString(da)
        # aaa.gachaId_=99
        # aaa.questId_=110080
        print(aaa)
        # print(aaa.SerializeToString().encode('hex'))
        return
    def mrck(self):    

        galist=['080510ad021801','08d2860310ad021801','08d3860310ad021801','08d4860310ad021801','08d5860310ad021801','08d6860310ad021801','08d8860310ae021801']
        for ga in galist:
            # time.sleep(5)
            try:
                print('do',ga)
                self.req_hex('/apb.api.gacha.GachaService/Draw',ga)    
                print('done',ga)
            except:
                print('error',ga)
    def domyac(self,cmd):
        global datahash
        self.initHeaders()
        self.signature_= "ojuxxOyDSA7EzB3qqN+jQqxnX2Sd5CgNqKN+E/RykTw="
        self.creds = grpc.ssl_channel_credentials(open('roots.pem','rb').read())
        self.channel = grpc.insecure_channel('prod-gs-grpc-nier.komoejoy.com:30002')
        self.mau()
        # datahash='prd/20220713110437'
        if datahash=='':
            datahash=self.GetLatestMasterDataVersion()
        print('datahash',datahash)
        self.meta['x-apb-master-data-hash']=datahash
        self.GetUserDataName()

        if cmd=='fl': #first login
            self.req_hex('/apb.api.data.DataService/GetUserData',open('battlereq/firstlogin','rb').read().hex())
            return
        self.getuser()
        self.CheckBeforeGamePlay()
        
        
        self.LoginBonusService_ReceiveStamp()
        
        if cmd=='mrck':
            self.mrck()
        elif cmd=='q':
            jsq=json.loads(open('battlereq/config').read())
            if len(sys.argv)<3:
                self.loadquest(jsq)
                return
            target=sys.argv[2]
            isfound=0
            for q in jsq:
                if q['fn']==target:
                    fnstep=q['fnstep']
                    isfound=1
                    ftype=q['ftype']
            if isfound==0:
                self.loadquest(jsq)
            else:
                if ftype==10:
                    qfun=self.doquest_jq
                elif ftype>0 and ftype<=4:
                    qfun=self.doquest_ty
                if len(sys.argv)>3:
                    times = int(sys.argv[3])
                else:
                    stamori=self.stam
                    if -1==qfun(fnstep):
                        return
                    self.getuser()
                    stamcost=stamori-self.stam
                    if stamcost<0:
                        stamcost=40
                    if stamcost!=0:
                        times=int(self.stam/stamcost-1)
                    else:
                        times=100000
                while times>0:
                    if -1==qfun(fnstep):
                        return
                    print('done '+sys.argv[2]+',',times,'left.')
                    times-=1
            self.getuser()
            print(self.stam)
        elif cmd=='qh':
            self.req_hex('/apb.api.weapon.WeaponService/EnhanceByMaterial','0a2436613034613337312d336435352d343762372d623963652d346232366165313361653238120608c19a0c1001')
        elif cmd=='get':
            para=str(sys.argv[2])
            self.getwhat(para)
        elif cmd=='qn':
            orijson=json.loads(open('battlerecord/config').read())
            newjson=json.loads(open('battlerecord/configwithstam').read())
            for obj in orijson:
                if obj not in newjson:
                    newjson[obj]=orijson[obj]
            keytodel=[]
            for obj in newjson:
                if obj not in orijson:
                    keytodel.append(obj)
            if len(keytodel)>0:
                for key in keytodel:
                    del newjson[key]
            open('battlerecord/configwithstam','w').write(json.dumps(newjson))
            # argv[0]=nese.py,[1]='qn',[2]=obj,[3]=times
            if len(sys.argv)<3 or sys.argv[2] not in newjson:
                print('need obj')
                for obj in newjson:
                    print(obj,newjson[obj])
                return
            objname=sys.argv[2]
            targettimes=1000
            if len(sys.argv)==4:
                targettimes=int(sys.argv[3])
            stamcost=0
            if len(newjson[objname])<4: # 未记录体力消耗
                stamori=self.stam
                if stamori<=40:
                    return
                self.doquest_event_new(newjson[objname][0],newjson[objname][1])
                self.getuser()
                stamcost=int(stamori-self.stam)
                newjson[objname].append(stamcost)
                open('battlerecord/configwithstam','w').write(json.dumps(newjson))
                nowtime=1
            else:
                stamcost=newjson[objname][3]
                nowtime=0
            if targettimes==1:
                return
            if stamcost==0:
                print('no stam cost, need input times')
            else:
                times=int(self.stam/stamcost-1)
                if  targettimes>times:
                    targettimes=times
                
                while nowtime<targettimes:
                      self.doquest_event_new(newjson[objname][0],newjson[objname][1])
                      nowtime+=1
                      print('now',nowtime,'targettimes',targettimes)
        elif cmd=='qe':
            # 周一1 1 100001
            # za11 99001 110008 
            # za21 99002 110018   za2b1 99002 110011    za2q1 99002 110012
            if len(sys.argv)<4:
                print('need eventQuestChapterId_ and questId_')
                pass
            eventQuestChapterId_= sys.argv[2]
            questId_=sys.argv[3]
            targettimes=1000
            if len(sys.argv)==5:
                targettimes=int(sys.argv[4])
            stamori=self.stam
            self.doquest_event_new(eventQuestChapterId_,questId_)
            self.getuser()
            if targettimes==1:
                return
            # targettimes-=1
            stamcost=stamori-self.stam
            if stamcost<0:
                stamcost=40
            if stamcost!=0:
                times=int(self.stam/stamcost-1)
                if  targettimes>times:
                    targettimes=times
            nowtime=1
            while nowtime<targettimes:
                  self.doquest_event_new(eventQuestChapterId_,questId_)
                  nowtime+=1
                  print('now',nowtime,'targettimes',targettimes)
        elif cmd=='qjqq':
            eqcid=99002
            qq=110012

            while qq<10100:
                print(qq)
                self.doquest_jq_new(qq)
                qq+=1
        elif cmd=='qjq':
            # 10065 第八章hard1
            if len(sys.argv)<3:
                print('need questId_')
                pass
            questId_=sys.argv[2]
            targettimes=0
            if len(sys.argv)==4:
                targettimes=int(sys.argv[3])
            stamori=self.stam
            self.doquest_jq_new(questId_)
            self.getuser()
            if targettimes==1:
                return
            targettimes-=1
            stamcost=stamori-self.stam
            if stamcost<0:
                stamcost=40
            if stamcost!=0:
                times=int(self.stam/stamcost-1)
                if targettimes<=0 or targettimes>times:
                    targettimes=times
            nowtime=0
            while nowtime<targettimes:
                  self.doquest_jq_new(questId_)
                  nowtime+=1
                  print('now',nowtime,'targettimes',targettimes)
        elif cmd=='qd':
            jsq=json.loads(open('battlereq/config').read())
            if len(sys.argv)<3: #所有每日1次全部打完
                for q in jsq:
                    if q['ftype']==4:
                        print(q['fncn'])
                        self.doquest_ty(q['fnstep'])
            else: #只打指定的，并且无掉落不结算
                target= sys.argv[2]    
                if target == 'a': #全部真暗掉落结算
                    print('do all')
                    total=0
                    totalstam=0
                    exceptlist=[]
                    for q in jsq:
                        if q['ftype']==4 and q['fn'] not in exceptlist:
                            tonext=0
                            while 1 and tonext==0:
                                print(q['fncn'],self.stam)
                                i=0
                                if self.stam>30:
                                    stamori=self.stam
                                    if 0!=self.doquest_qd(q['fnstep']):
                                        print('get')
                                        tonext=1
                                        break
                                    self.getuser()
                                    stamcost=stamori-self.stam
                                    times=self.stam/stamcost-1
                                    while i<times:
                                        totalstam+=stamcost
                                        if 0==self.doquest_qd(q['fnstep']):
                                            print('no drop, try next',i,total,totalstam)
                                        else:
                                            print('get')
                                            tonext=1
                                            break
                                        i+=1
                                        total+=1
                                self.getuser()
                                if self.stam<30:
                                    self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171055')
                                self.getuser()
                            
                else:
                    for q in jsq:
                        if q['fn']==target:
                            total=0
                            while 1:
                                print(q['fncn'],self.stam)
                                i=0
                                if self.stam>30:
                                    stamori=self.stam
                                    if 0!=self.doquest_qd(q['fnstep']):
                                        print('get')
                                        return
                                    self.getuser()
                                    stamcost=stamori-self.stam
                                    times=self.stam/stamcost-1
                                    while i<times:
                                        if 0==self.doquest_qd(q['fnstep']):
                                            print('no drop, try next',i,total,times-i)
                                        else:
                                            print('get')
                                            return
                                        i+=1
                                        total+=1
                                self.getuser()
                                if self.stam<30:
                                    self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171055')
                                self.getuser()
                            
        elif cmd=='pb': #跑步
            c=pb.CageMeasurableValues(runningDistanceMeters_=10000,mamaTappedCount_=150)
            body=pb.GetMamaBannerRequest(c=c).SerializeToString()
            self.req_hex('/apb.api.mission.MissionService/UpdateMissionProgress',body.encode('hex'))
        elif cmd=='pvp':
            while 1:
                self.dopvp()
                print('done pvp')
        elif cmd=='tly1': #体力药小08b9171001
            if self.stam>150:
                print(self.stam)
                return
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171047')
            self.getuser()
            print(self.stam)
        elif cmd=='tly2': #体力药中
            if self.stam>150:
                print(self.stam)
                return
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08ba17100a')
            self.getuser()
            print(self.stam)
        elif cmd=='tly3': #体力药大
            if self.stam>150:
                print(self.stam)
                return
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08bb171005')
            self.getuser()
            print(self.stam)
        elif cmd=='ts':
            print(self.stam)
            self.StartExplore(1)
            # time.sleep(100)
            self.FinishExplore(1)
            self.getuser()
            print(self.stam)
        elif cmd=='tsq':
            while 1:
                self.StartExplore(1,2001)
                # time.sleep(100)
                self.FinishExplore(1)
                self.getuser()
                print(self.stam)
                if self.stam>600:
                    return

        elif cmd=='sb':  #买体力药
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','')
            self.req_hex('/apb.api.shop.ShopService/Buy','08d10f120608d19a0c1014')
            self.getuser()
            print(self.gold)
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','0801')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','')
            self.req_hex('/apb.api.shop.ShopService/Buy','08d10f120608d19a0c1014')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','0801')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','')
            self.req_hex('/apb.api.shop.ShopService/Buy','08d10f120608d19a0c1014')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','0801')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','')
            self.req_hex('/apb.api.shop.ShopService/Buy','08d10f120608d19a0c1014')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','0801')
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','')
            self.req_hex('/apb.api.shop.ShopService/Buy','08d10f120608d19a0c1014')
            self.getuser()
            print(self.gold)
        elif cmd=='m':
            self.cleanmail()
        elif cmd=='hdck':
            times=1000
            roll=7
            hdid=300000
            # times=int(sys.argv[3])
            # roll=int(sys.argv[2])
            # try:
            #     while 1:
            self.GachaService_Draw(hdid+roll,hdid+roll,times)
            print('gacha done')
            self.GachaService_ResetBoxGachaRequest(hdid+roll)
            # except:
                # print('no more ticket')
            
            return
        elif cmd=='sp':
            # while 1:
            self.partslist()
        elif cmd=='rw': #任务
            self.req_hex('/apb.api.mission.MissionService/ReceiveMissionRewardsById','0a0701020304050706')
    def partslist(self):
        parts_dic = self.partslistinit()
        # 属性过滤
        tosave = []
        need=['PT_ATTACK','CRITICAL_ATTACK','CRITICAL_RATIO']
        for part in parts_dic:
            print(parts_dic[part])
            if ( \
                parts_dic[part].__contains__('PT_ATTACK') and 'x' == parts_dic[part]['PT_ATTACK'][0]\
            and parts_dic[part].__contains__('CRITICAL_ATTACK') \
            and parts_dic[part].__contains__('CRITICAL_RATIO') \
            # and 60 == parts_dic[part]['CRITICAL_ATTACK'][1]\
            # and 50 == parts_dic[part]['CRITICAL_RATIO'][1]  \
            ) \
            or parts_dic[part]['level']!=1:
            # if parts_dic[part]['level']!=1: #sell all
            # if  need[0] in parts_dic[part] and need[1] in parts_dic[part] and need[2] in parts_dic[part]:
                # print part,parts_dic[part]
                print(parts_dic[part])
                tosave.append(part)
        # return
        print('to save',len(tosave))
        # print(tosave)
        # rev=all_parts_dic
        todelete = []
        for line in parts_dic:
            # print line
            if line not in tosave : #and parts_dic[line]['level']==1
                todelete.append(line)
        print('to delete',len(todelete))
        # return
        if len(todelete)>1:
            self.sellpbycon(todelete)
        
        # return
        #升级
        for line in tosave:
            sc =0
            # try:  
            while sc<15-parts_dic[line]['level']:
                sc+=self.enhance(line)
                # print '\r',sc,
            print('done', end=' ')
            sys.stdout.flush()
    def partslistinit(self):
        whitelist=[8020,8040,8060]
        a=['IUserParts','IUserPartsStatusSub']
        rev0=self.GetUserData(a)
        rev=json.loads(rev0.userDataJson_[a[0]])
        print(len(rev))
        print(rev)
        parts_dic={}
        for line in rev:
            # print(line)
            name = str(line['userPartsUuid'])
            if line['partsId'] in whitelist and  name not in parts_dic :
                # print line
                parts_dic[name]={'id':line['partsId'],'level':line['level']}
        # all_parts_dic = parts_dic


        statuskind=['UNKNOWN','AGILITY','PT_ATTACK','CRITICAL_ATTACK','CRITICAL_RATIO','EVASION_RATIO','HP','VITALITY']
        statustype=['UNKNOWN','+','x']
        statusmax=[0,0,0,60,50,0,0,0]
        # max_ca=0
        # max_cr=0
        # max_atk=0
        rev=json.loads(rev0.userDataJson_[a[1]])
        print('total:', len(rev))
        for line in rev:
            name = str(line['userPartsUuid'])
            if name  in parts_dic:
                # str1 = statuskind[line['statusKindType']]+statustype[line['statusCalculationType']]+str(line['statusChangeValue'])+'('+str(line['level'])+')'
                parts_dic[name][statuskind[line['statusKindType']]]=[statustype[line['statusCalculationType']],line['statusChangeValue'],line['level']]
                # if line['statusCalculationType'] == 2 and line['statusChangeValue'] > statusmax[line['statusKindType']] :
                #     statusmax[line['statusKindType']] = line['statusChangeValue']
            else:
                # print line
                pass
        print('parts_dic:', len(parts_dic))
        return parts_dic
    def enhance(self,uuid):
        
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.EnhanceRequest(userPartsUuid_= uuid).SerializeToString()
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.parts.PartsService/Enhance',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.EnhanceResponse.FromString(rev)
        return revj.issuccess
    def sellpbycon(self,parts):
        if len(parts)<1:
            return
        todelete=[]
        count=0
        i=0
        print(len(parts),'to sell')
        while i<len(parts):
            todelete.append(str(parts[i]))
            count+=1
            if count>=10:
                print('sell', end=' ')
                self.sellparts(todelete)        
                count=0
                todelete=[]
                sys.stdout.flush()
            i+=1
        if len(todelete)>0:
            self.sellparts(todelete)



    def sellparts(self,parts):
        # print '>call /apb.api.explore.ExploreService/StartExplore'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SellRequest(userWeaponUuid_= parts).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.parts.PartsService/Sell',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def mau(self):
        rev=self.req_hex('/apb.api.user.UserService/Auth','0a1331353437343232363634393435303431343038122c6f6a7578784f7944534137457a423371714e2b6a5171786e583253643543674e714b4e2b452f52796b54773d1a2430303030303030302d303030302d303030302d303030302d3030303030303030303030303282027b227472223a5b7b227469223a226c72222c22626f223a22227d2c7b227469223a22696a62222c22626f223a2254727565227d2c7b227469223a22686967222c22626f223a2246616c7365227d2c7b227469223a22616373222c22626f223a22227d2c7b227469223a22706572222c22626f223a2246616c7365227d2c7b227469223a22696d75222c22626f223a2246616c7365227d2c7b227469223a226972222c22626f223a2246616c7365227d2c7b227469223a226961222c22626f223a2246616c7365227d2c7b227469223a226d73222c22626f223a2253797374656d2e537472696e675b5d227d2c7b227469223a22696373222c22626f223a22227d5d7d3a81020a13313534373432323636343934353034313430381a203235393439333832616237306638653263623234663036333130333030323766320f757365725f333630373138373236353a04313635304094384a06312e332e333850b9175a0f757365725f333630373138373236356213313534373432323636343934353034313430386801724e41463036454330342d314542422d343333412d424143332d3438443335394232433130363b694f532031342e333b6950686f6e6531322c353b636f6d2e6b6f6d6f652e6e6965727265696e696f737a045769666982012446453943353733452d464538452d343632352d424536302d363730313032303232443346')
        revj=pb.AuthUserResponse.FromString(rev)
        # print(revj)
        self.sessionKey_=str(revj.sessionKey_)
        self.meta['x-apb-session-key']= self.sessionKey_
        self.meta['x-apb-master-data-hash']=''
    def LoginBonusService_ReceiveStamp(self):
        # print '>call LoginBonusService/ReceiveStamp'
        metadata=self.refreshMetadata()
        # print metadata
        body=''
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.loginBonus.LoginBonusService/ReceiveStamp',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def TutorialService_SetTutorialProgressRequest(self,ty,ph):
        # print '>call TutorialService/SetTutorialProgressRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SetTutorialProgressRequest(tutorialType_=ty,progressPhase_=ph).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.tutorial.TutorialService/SetTutorialProgress',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def CheckBeforeGamePlay(self):
        # print '>call CheckBeforeGamePlay'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.CheckBeforeGamePlay()
        body=body.SerializeToString()
        
        body=self.encb(body)
        
        requester = self.channel.unary_unary('/apb.api.gameplay.GamePlayService/CheckBeforeGamePlay',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.differResponse.FromString(rev)
    def QuestService_UpdateMainQuestSceneProgress(self,p1va):
        # print '>call QuestService/UpdateMainQuestSceneProgress'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.intmessage(p1=p1va).SerializeToString()
        
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/UpdateMainQuestSceneProgress',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def StartExplore(self,exploreId_,useConsumableItemId_=0):
        # print '>call /apb.api.explore.ExploreService/StartExplore'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.StartExploreRequestReq(exploreId_= exploreId_,useConsumableItemId_=useConsumableItemId_).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.explore.ExploreService/StartExplore',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def FinishExplore(self,exploreId_):
        # print '>call /apb.api.explore.ExploreService/FinishExplore'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.FinishExploreRequest(exploreId_= exploreId_,score_=107650).SerializeToString()+bytes.fromhex('c20c28')+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        # print(body.encode('hex'))
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.explore.ExploreService/FinishExplore',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.FinishExploreResponse()
        aaa.ParseFromString(rev)
        print(aaa)
    def QuestService_StartMainQuest(self,qid,isMainFlow=True,userDeckNumber=1):
        # print '>call QuestService/StartMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.StartMainQuest(questId_= qid,isMainFlow_= isMainFlow,userDeckNumber_=userDeckNumber).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/StartMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def GachaService_ResetBoxGachaRequest(self,gachaId_):
        # print '>call GachaService/GetGachaList'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.ResetBoxGachaRequest(gachaId_=gachaId_).SerializeToString()
        # body='08e7a712'.decode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gacha.GachaService/ResetBoxGacha',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.differResponse2.FromString(rev)
    def GachaService_Draw(self,gachaId_,gachaPricePhaseId_,execCount_):
        # print '>call GachaService/Draw',gachaId_,gachaPricePhaseId_,execCount_
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.DrawRequest(gachaId_=gachaId_,gachaPricePhaseId_=gachaPricePhaseId_,execCount_=execCount_).SerializeToString()
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gacha.GachaService/Draw',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.DrawResponse.FromString(rev)
        # print revj
        return revj
    def QuestService_FinishMainQuest(self,qid,isMainFlow=True):
        # print '>call QuestService/FinishMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.FinishMainQuestRequest(questId_=qid,isMainFlow_=isMainFlow,storySkipType_=1,isRetired_=0)
        # print body
        # body = body.SerializeToString()+self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body = bytes.fromhex('08'+str("%02x"%qid)+'18013001c20c28')+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_UpdateMainFlowSceneProgress(self,qid):
        # print '>call QuestService/UpdateMainFlowSceneProgress'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.UpdateMainFlowSceneProgress(questSceneId_=qid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/UpdateMainFlowSceneProgress',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def cailiaoSellRequestReqById(self,clid):
        # print '>call /apb.api.explore.ExploreService/StartExplore'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.cailiaoSellRequest(materialPossession_=[pb.SellPossession(materialId_=clid,count_=99999)]).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.material.MaterialService/Sell',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def cleanmail(self):
        revj=self.GiftService_GetGiftList()
        lastgift =''
        while len(self.pre_list)>0:
            print(len(self.pre_list),self.pre_list[0])
            if lastgift == self.pre_list[0]:
                nowgift=revj.gift_[0]
                print('declipe maybe, ',nowgift.userGiftUuid_==self.pre_list[0])
                if  nowgift.userGiftUuid_==self.pre_list[0]:
                    if nowgift.GiftCommon_.possessionType_==5:
                        ptype=nowgift.GiftCommon_.possessionId_
                        self.cailiaoSellRequestReqById(ptype)
                return
            lastgift = self.pre_list[0]
            self.GiftService_ReceiveGift()
            self.GiftService_GetGiftList()
            print('done')
    def GiftService_GetGiftList(self):
        # print '>call GiftService/GetGiftList'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.GetGiftListRequest(rewardKindType_=[1],expirationType_=1,getCount_=20).SerializeToString()

        # 0a070207040506080910013014  不包含金币
        body=bytes.fromhex('0a070207040506080910013014')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gift.GiftService/GetGiftList',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.GetGiftListResponse.FromString(rev)
        # print revj
        self.pre_list=[]
        for a in revj.gift_:
            self.pre_list.append(str(a.userGiftUuid_))
    def GiftService_ReceiveGift(self):
        # print '>call GiftService/ReceiveGift'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.ReceiveGiftRequest(uuid_=self.pre_list).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gift.GiftService/ReceiveGift',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def req_binq(self,path,binq,needsign=0):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=open('battlereq/'+binq,'rb').read()
        if needsign==1:
            body=bytes(body[:-40])+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_binq_new(self,path,binq,needsign=0):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=open('battlerecord/'+binq,'rb').read()
        if needsign==1:
            body=bytes(body[:-40])+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_binq_EventQuest_start(self,path,binq,eventQuestChapterId_,questId_):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        body=open('battlerecord/'+binq,'rb').read()[:-40]
        aaa=pb.StartEventQuest()
        aaa.ParseFromString(body)
        aaa.eventQuestChapterId_=int(eventQuestChapterId_)
        aaa.questId_=int(questId_)
        aaa.userDeckNumber_=3
        body=aaa.SerializeToString()+bytes.fromhex('1804')
        # print(''.join(['%02X' % b for b in body]))
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_binq_MainQuest_start(self,path,binq,questId_):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        body=open('battlerecord/'+binq,'rb').read()[:-40]
        aaa=pb.StartMainQuest()
        aaa.ParseFromString(body)
        aaa.questId_=int(questId_)
        aaa.userDeckNumber_=4
        body=aaa.SerializeToString()+bytes.fromhex('1804')
        # print(''.join(['%02X' % b for b in body]))
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_binq_EventQuest_end(self,path,binq,eventQuestChapterId_,questId_):
        # print('>call ',path,binq)
        metadata=self.refreshMetadata()
        body=open('battlerecord/'+binq,'rb').read()
        aaa=pb.FinishEventQuestRequest()
        aaa.ParseFromString(body)
        aaa.eventQuestChapterId_=int(eventQuestChapterId_)
        aaa.questId_=int(questId_)
        body=aaa.SerializeToString()
        body=bytes(body[:-40])+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_binq_MainQuest_end(self,path,binq,questId_):
        # print('>call ',path,binq)
        metadata=self.refreshMetadata()
        body=open('battlerecord/'+binq,'rb').read()
        aaa=pb.FinishMainQuestRequest()
        aaa.ParseFromString(body)
        aaa.questId_=int(questId_)
        body=aaa.SerializeToString()
        body=bytes(body[:-40])+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_hex(self,path,binq,needsign=0):
        # print '>call ',path
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=bytes.fromhex(binq)
        if needsign==1:
            body=bytes(body[:-40])+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def GetUserDataName(self):
        # print '>call GetUserDataName'
        metadata=self.refreshMetadata()
        # print metadata
        body=''
        # body=body.SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.data.DataService/GetUserDataName',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
    def GetLatestMasterDataVersion(self):
        # print '>call GetLatestMasterDataVersion'
        metadata=self.refreshMetadata()
        # print metadata
        body=''
        # body=body.SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.data.DataService/GetLatestMasterDataVersion',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        rev=pb.stringResponse.FromString(rev)
        # print rev
        # print rev.encode('hex')
        print(str(rev.str))
        self.meta['x-apb-master-data-hash']=str(rev.str)
        return str(rev.str)
    def GetUserData(self,tableName_):
        # print '>call GetUserData'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.UserDataGetRequest(tableName_=tableName_).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.data.DataService/GetUserData',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.UserDataGetResponse.FromString(rev)
        return revj
    def getwhat(self,para):
        rev=self.GetUserData([para])
        print(rev)
    def getuser(self):
        rev=self.GetUserData(["IUserGem","IUser","IUserStatus","IUserEventQuestProgressStatus","IUserMainQuestProgressStatus"])
        self.stam=int(json.loads(rev.userDataJson_['IUserStatus'])[0]['staminaMilliValue'])/1000
        self.playerId= int(json.loads(rev.userDataJson_['IUser'])[0]['playerId'])
        self.gold= int(json.loads(rev.userDataJson_['IUserGem'])[0]['freeGem'])
        self.my_slist=[]
        self.my_chara=[]
        rtt=rev
        rev=json.loads(rev.userDataJson_['IUserEventQuestProgressStatus'])
        # print rev
        if rev[0]['currentEventQuestChapterId']!=0:
            eventQuestChapterId_ = rev[0]['currentEventQuestChapterId']
            questId_ = rev[0]['currentQuestId']
            da=bytes.fromhex('08c4850610bcdc0618013001c20c2834313962376461306133626636643766633763326363633165613063623239383139326566376166')
            aaa=pb.FinishEventQuestRequest()
            aaa.ParseFromString(da)
            aaa.eventQuestChapterId_=eventQuestChapterId_
            aaa.questId_=questId_
            self.QuestService_FinishEventQuest_retired(aaa.SerializeToString()[:-40])
        else:
            print('no old mission to stop')
        rev=json.loads(rtt.userDataJson_['IUserMainQuestProgressStatus'])
        # print rev
        if rev[0]['currentQuestSceneId']!=0:
            eventQuestChapterId_ = rev[0]['currentQuestSceneId']
            questId_ = rev[0]['headQuestSceneId']
            da=bytes.fromhex('08fb4e10013001c20c2862333766663435646638653664313930373631653133656636633130326261663934353966643163')
            aaa=pb.FinishMainQuestRequest()
            aaa.ParseFromString(da)
            # aaa.eventQuestChapterId_=eventQuestChapterId_
            aaa.questId_=questId_
            self.QuestService_FinishMainQuest_retired(aaa.SerializeToString()[:-40])
        else:
            print('no old mission to stop')
    def QuestService_FinishMainQuest_retired(self,aaa):
        # print '>call QuestService/FinishMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.FinishMainQuestRequest(questId_=qid,isMainFlow_=isMainFlow,storySkipType_=1,isRetired_=0)
        # print body
        # body = body.SerializeToString()+self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=bytes(aaa)+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def dopvp(self):
        pid=self.PvpService_GetMatchingList()
        self.PvpService_StartBattle(pid)
        self.PvpService_FinishBattle(pid)
    def PvpService_GetMatchingList(self):
        # print '>call /apb.api.friend.FriendService/SendFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.UpdateEventQuestSceneProgressReq(questSceneId_= pid).SerializeToString()
        body=self.encb('')
        requester = self.channel.unary_unary('/apb.api.pvp.PvpService/GetMatchingList',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.GetMatchingListResponse()
        aaa.ParseFromString(rev)
        return aaa.matching_[0].playerId_
    def PvpService_StartBattle(self,pid):
        # print '>call /apb.api.friend.FriendService/SendFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.StartBattleRequest(opponentPlayerId_= pid,useDeckNumber_=1).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.pvp.PvpService/StartBattle',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def PvpService_FinishBattle(self,pid):
        # print '>call /apb.api.friend.FriendService/SendFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.FinishBattleRequest(opponentPlayerId_= pid,isVictory_=1).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.pvp.PvpService/FinishBattle',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_FinishEventQuest_retired(self,aaa):
        # print '>call QuestService_FinishEventQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=bytes(aaa)+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)

        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishEventQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def getdrop(self,dp):
        for a in dp.battleDropReward_:
            # if a.battleDropEffectId_>=2:
            print(a.battleDropEffectId_,end=' ')
            if a.battleDropEffectId_==3:
                print('hit')
                return 1
        print('t:',len(dp.battleDropReward_))
        return 0
    def doquest_qd(self,fnstep):
        if len(fnstep)==8:
            rev=self.req_binq('/apb.api.quest.QuestService/StartEventQuest',fnstep[0][0],fnstep[0][1])
            revj=pb.StartEventQuestResponse.FromString(rev)
            if 1==self.getdrop(revj):
                self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
                self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
                self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[3][0],fnstep[3][1])
                self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[4][0],fnstep[4][1])
                self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[5][0],fnstep[5][1])
                self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[6][0],fnstep[6][1])
                self.req_binq('/apb.api.quest.QuestService/FinishEventQuest',fnstep[7][0],fnstep[7][1])
                return 1
            else:
                lastreq=open('battlereq/'+str(fnstep[7][0]),'rb').read()
                aaa=pb.FinishEventQuestRequest()
                aaa.ParseFromString(lastreq)
                aaa.isRetired_=True
                open('battlereq/tmp_last','wb').write(aaa.SerializeToString())
                self.req_binq('/apb.api.quest.QuestService/FinishEventQuest','tmp_last',fnstep[7][1])
            return 0
    def doquest_ty(self,fnstep):
        if len(fnstep)==8:
            # self.req_binq('/apb.api.quest.QuestService/FinishEventQuest',fnstep[7][0],fnstep[7][1])
            rev=self.req_binq('/apb.api.quest.QuestService/StartEventQuest',fnstep[0][0],fnstep[0][1])
            revj=pb.StartEventQuestResponse.FromString(rev)
            self.getdrop(revj)
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[3][0],fnstep[3][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[4][0],fnstep[4][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[5][0],fnstep[5][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[6][0],fnstep[6][1])
            self.req_binq('/apb.api.quest.QuestService/FinishEventQuest',fnstep[7][0],fnstep[7][1])
            return 0
        elif len(fnstep)==4:
            self.req_binq('/apb.api.quest.QuestService/StartEventQuest',fnstep[0][0],fnstep[0][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
            self.req_binq('/apb.api.quest.QuestService/FinishEventQuest',fnstep[3][0],fnstep[3][1])
            return 0
        print('step wrong')
        return -1
    def doquest_test(self,fnstep,eventQuestChapterId_,questId_):
        self.req_binq_EventQuest_start('/apb.api.quest.QuestService/StartEventQuest',fnstep[0][0],eventQuestChapterId_,questId_)
        self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
        self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
        self.req_binq_EventQuest_end('/apb.api.quest.QuestService/FinishEventQuest',fnstep[3][0],eventQuestChapterId_,questId_)
        return 0
    def doquest_jq_new(self,questId_):
        rev=self.req_binq_MainQuest_start('/apb.api.quest.QuestService/StartMainQuest','MainQuest_1',questId_)
        revj=pb.StartEventQuestResponse.FromString(rev)
        # self.getdrop(revj)
        self.req_binq_new('/apb.api.battle.BattleService/StartWave','MainQuest_2',0)
        self.req_binq_new('/apb.api.battle.BattleService/FinishWave','MainQuest_3',1)
        self.req_binq_new('/apb.api.battle.BattleService/StartWave','MainQuest_4',0)
        self.req_binq_new('/apb.api.battle.BattleService/FinishWave','MainQuest_5',1)
        self.req_binq_new('/apb.api.battle.BattleService/StartWave','MainQuest_6',0)
        self.req_binq_new('/apb.api.battle.BattleService/FinishWave','MainQuest_7',1)
        self.req_binq_MainQuest_end('/apb.api.quest.QuestService/FinishMainQuest','MainQuest_8',questId_)
        return 0
    def doquest_event_new(self,eventQuestChapterId_,questId_):
        self.req_binq_EventQuest_start('/apb.api.quest.QuestService/StartEventQuest','EventQuest_1',eventQuestChapterId_,questId_)
        self.req_binq_new('/apb.api.battle.BattleService/StartWave','EventQuest_2',0)
        self.req_binq_new('/apb.api.battle.BattleService/FinishWave','EventQuest_3',1)
        self.req_binq_EventQuest_end('/apb.api.quest.QuestService/FinishEventQuest','EventQuest_4',eventQuestChapterId_,questId_)
        return 0

    def doquest_jq(self,fnstep):
        if len(fnstep)==8:
            rev=self.req_binq('/apb.api.quest.QuestService/StartMainQuest',fnstep[0][0],fnstep[0][1])
            revj=pb.StartEventQuestResponse.FromString(rev)
            # self.getdrop(revj)
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[3][0],fnstep[3][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[4][0],fnstep[4][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[5][0],fnstep[5][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[6][0],fnstep[6][1])
            self.req_binq('/apb.api.quest.QuestService/FinishMainQuest',fnstep[7][0],fnstep[7][1])
            return 0
        elif len(fnstep)==4:
            self.req_binq('/apb.api.quest.QuestService/StartEventQuest',fnstep[0][0],fnstep[0][1])
            self.req_binq('/apb.api.battle.BattleService/StartWave',fnstep[1][0],fnstep[1][1])
            self.req_binq('/apb.api.battle.BattleService/FinishWave',fnstep[2][0],fnstep[2][1])
            self.req_binq('/apb.api.quest.QuestService/FinishMainQuest',fnstep[3][0],fnstep[3][1])
            return 0
        print('step wrong')
        return -1
    def loadquest(self,jsq):
        nowtype=1
        while nowtype<20:
            for a in jsq:
                # print a['fn'],a['fncn']
                if nowtype!=4 and a['ftype']==nowtype:
                    print(a['fn'],a['fncn'])
            nowtype+=1
    def loadquestjq(self,jsq):
        nowtype=1
        for a in jsq:
            if a['ftype']==10:
                print(a['fn'],a['fncn'])
    def refreshMetadata(self):
        self.meta['x-apb-request-datetime']=str(int(time.time()))
        self.meta['x-apb-request-id']='1'+(str(random.random())+str(random.random())).replace('.','')[1:19] #str(int(self.meta['x-apb-request-id'])+1)
        return tuple( (x,self.meta[x]) for x in self.meta)
    def encb(self,da):
        # time.sleep(6)
        enckey='1234567890ABCDEF'
        enciv='it8bAjktKdFIBYtU'
        # enckey='EfcAef4CAe5f6DaA'
        # enciv='6Cb01321EE5e6bBe'
        return self.rijndael_enc(da,enckey,enciv)
    def decb(self,da):
        # key='6Cb01321EE5e6bBe'
        # iv='EfcAef4CAe5f6DaA'
        enckey='1234567890ABCDEF'
        enciv='it8bAjktKdFIBYtU'
        return self.rijndael_dec(da,enckey,enciv)
    def rijndael_dec(self,todec,key,iv):
        from Crypto.Cipher import AES
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        return unpad(cryptor.decrypt(todec))
    def rijndael_enc(self,toenc,key,iv):
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
        cryptor = AES.new(key, AES.MODE_CBC, iv)
        # toenc = self.pad(toenc)
        # BLOCK_SIZE=16
        # pad = lambda s: str(s) + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
        # print(len(toenc))
        # pad = lambda s: s + (BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s.encode()) % BLOCK_SIZE)
        # toenc = pad(toenc)
        # print(toenc,len(toenc))
        if len(toenc) > 0:
            toenc = bytes(Padding.pad(toenc,16,'pkcs7'))
        # print(len(toenc))
        return cryptor.encrypt(toenc)
        # return rjn.encrypt(toenc)
    def unpad(self, text):
        pad = ord(text[-1])
        return text[:-pad]
    def pad(self,k):
        if 16 > len(k):
            padding = 16 - len(k)
            k = k + chr(padding).encode('utf-8')*padding
        elif 16 < len(k):
            padding = 16 - (len(k)%16)
            k = k + chr(padding).encode('utf-8') * padding
        else:
            k = k + chr(16).encode('utf-8') * 16
        return k
    def ruencb(self,da):
        # print da
        return da
        # pass
    def redecb(self,da):
        # print da
        return da
    def reloadmeta(self,meta):
        # print meta
        for a in meta:
            if a.key=='x-apb-token':
                self.meta['x-apb-token']=a.value
k=reqfuncmjzj()
if len(sys.argv)>1:
    k.domyac(sys.argv[1])
else:
    k.aa()
