# -*- coding: utf-8 -*-
import base64,uuid,urllib3,json,threading,sys,time,random,string,collections,zlib
import socket
import importlib
urllib3.disable_warnings()
import pycurl
import grpc
import helloworld_pb2 as pb
import helloworld_pb2_grpc as func
import uuid
from functools import partial
# import helloworld_pb2 as helloworld__pb2
datahash=''
import sys
importlib.reload(sys)
sys.setdefaultencoding('utf8')
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
'x-apb-app-version': '2.4.20',
'x-apb-language': 'ChineseSimplified',
'x-apb-os-version': 'iOS 13.5',
'x-apb-device-name': 'iPhone12,5',
'x-apb-os-type': '1',
'x-apb-platform-type': '1',
# 'x-apb-request-datetime': str(int(time.time())),
# 'x-apb-request-id': '5159406471191185408',
'x-apb-user-id': '0',
'x-apb-session-key': '',
'x-apb-token': '',
'x-apb-master-data-hash': '',
# 'x-apb-keychain-user-id': '1984276123488029583',
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
        m2.update(data)
        return m2.hexdigest()
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
        # da='31343439373330393035313332333737323134327144484a74'
        # da=da.decode('hex')
        # print (self.gensha1(da))
        # return
        # da=open('aaa').read()
        # da='feffacd3af6e789c496bb665d2d564f2c05de11d2ea0388239ff46c99723ab4be653284c6b125694d6bd276926179a630deeed1191f4b68924ad62f70ef0ead5'.decode('hex')
        # key='dead765x'
        # da='Mn99DSby2gO9LRI520b35yWpJfU94OQfFAen8biR9qRok1iYskO9PyZvTDnjg1B1RX/hZ4R//F5vE7eLpB3WRmfwAXo6V+byeA4SulYm/HLn2+lze1ATrVcxALjXWrKHp6nh6QKlzO1j8jjKlVlHgzi1lOzG/LUTty8Up3NEGd0O4OPN5Zuk2z0S4HjFBV1aW8y/P+cg6ZwLruBKWH3PmunKFrAkyc3r52E3oE0+m4wiEV3D8RA4KBBcCVIAjSj1moPSLaxZuGFIcL+apbmIWdIOOVuuUcJtT/jQm/ESq+XMAfZ4PFklV4JUe8X7actawzgiRptl/A4kCKv+UCvSTx6wqbedI893AX7S0nNdxkS4NPWETWhLFVsGkv1o7B8jglR7xftpy1rDOCJGm2X8DiQIq/5QK9JPHrCpt50jz3cBftLSc13GRBIWyiQ4fa90HY3HR9Kk9vXQ5ykhC0HJN8RD9ZOw4AVYmHg1eOLtwkaXK+OJ5IjpamdfRXHi06Z8J1QCt5ZWGzlxcc0jEMUVncrELqDyWItgO/jNG4CadvhJQxJIHxx+6ziU4Zv79qTva6j8aLIfgjg09IEwXB9vmZ+iQceP4fCTPjV4+Ep5cDE1SjN7LRIPv7xsy8vdCLLBO/dNyr6eMZE='
        # da=base64.b64decode(da)
        # # # key='6Cb01321EE5e6bBe'
        # # # iv='EfcAef4CAe5f6DaA'
        # dec= self.des_ecb_dec(da,key)
        # print dec
        # # da=self.des_ecb_enc(dec,key)
        # # da=base64.b64encode(da)
        # # print da
        # return
        # a=self.encb(dec)
        # open('enca','wb').write(a)
        # print a.encode('hex')
        # return 
        # c=pb.CageMeasurableValues(runningDistanceMeters_=10,mamaTappedCount_=10)
        # body=pb.GetMamaBannerRequest(c=c).SerializeToString()
        # print body.encode('hex')

        # body=pb.FinishExploreRequest(exploreId_= 1,score_=485250).SerializeToString()+'c20c28'.decode('hex')+'39633736373737393066306437613666363531343865333732623962383331656161303539346534'.decode('hex')
        # print body.encode('hex')
        # da=body
        da='080510ad021801'.decode('hex')
        # print da.encode('hex')
        # da=open('battlereq/111').read()
        # print da.encode('hex')
        # da=da.decode('hex')
        aaa=pb.DrawRequest()
        aaa.ParseFromString(da)
        aaa.gachaId_=99
        # aaa.questId_=110080
        print(aaa)
        print(aaa.SerializeToString().encode('hex'))
        # open('battlereq/111','wb').write(aaa.SerializeToString())
        # encb=self.encb(da)
        # print encb.encode('hex')
        return
    def doacbyyjm(self,yjm):
        self.initHeaders()
        self.uuid="235e2a56-9501-4bed-9f21-9f3db8571cb8"
        self.terminalId_ =   "00000000-0000-0000-0000-000000000000"
        self.signature_= "3cJsXeZ9aNInpvZ8YBdk1TvJ3nD9g8oc1g3gXupqxsk="
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('prod-gs-grpc-nier.komoejoy.com:30002',self.creds)
        self.userId_='1649394160118177959'
        self.Auth()
        self.GetLatestMasterDataVersion()
        self.getuser()
        print('stam:', self.stam)
    def deletefriendandfriendrequest(self):
        self.GetFriendList()
        i=0
        ilen=len(self.my_friend)
        for f in self.my_friend:
            i+=1
            showjd(i,ilen)
            self.DeleteFriendRequest(f)
        self.GetFriendRequestList()
        i=0
        ilen=len(self.my_friend_request)
        for f in self.my_friend_request:
            i+=1
            showjd(i,ilen)
            self.DeclineFriendRequest(f)
    def dozbac(self,cmd,yjm):
        global datahash,g_friend_list
        key='1231231231231231'
        yjm= base64.b64decode(yjm)
        acdata=self.aes_128_ecb_dec(yjm,key).split(' ')
        # print acdata
        self.initHeaders()
        self.uuid=acdata[0]
        self.signature_=acdata[1]
        self.userId_=acdata[2]
        self.terminalId_ =   "00000000-0000-0000-0000-000000000000"
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('api.app.nierreincarnation.jp:443',self.creds)
        self.Auth()
        if datahash=='':
            datahash=self.GetLatestMasterDataVersion()
        # print 'datahash',datahash
        self.meta['x-apb-master-data-hash']=datahash
        if cmd=='step1':
            self.deletefriendandfriendrequest()
            self.SendFriendRequest(g_friend_list[0])
        elif cmd=='step2':
            self.GetFriendList()
            # print '\nmftr',self.my_friend_toreceive
            for f in self.my_friend_toreceive:
                self.ReceiveCheer(f)
            for f in self.my_friend_tosend:
                self.CheerFriend(f)
        elif cmd=='step3':
            self.deletefriendandfriendrequest()
    def mau(self):
        rev=self.req_hex('/apb.api.user.UserService/Auth','0a2430366664653864622d623737332d343937362d626563352d383363346466616464633338122c33634a7358655a39614e496e70765a385942646b3154764a336e443967386f63316733675875707178736b3d1a2431413441413245352d313431392d344543362d394134422d31353346304343354533464520013282027b227472223a5b7b227469223a226c72222c22626f223a22227d2c7b227469223a22696a62222c22626f223a2254727565227d2c7b227469223a22686967222c22626f223a2246616c7365227d2c7b227469223a22616373222c22626f223a22227d2c7b227469223a22706572222c22626f223a2246616c7365227d2c7b227469223a22696d75222c22626f223a2246616c7365227d2c7b227469223a226972222c22626f223a2246616c7365227d2c7b227469223a226961222c22626f223a2246616c7365227d2c7b227469223a226d73222c22626f223a2253797374656d2e537472696e675b5d227d2c7b227469223a22696373222c22626f223a22227d5d7d')
        revj=pb.AuthUserResponse.FromString(rev)
        # print revj
        self.sessionKey_=str(revj.sessionKey_)
        self.meta['x-apb-user-id']= self.userId_
        self.meta['x-apb-session-key']= self.sessionKey_
        # self.meta['x-apb-master-data-version']= '0'
        self.meta['x-apb-master-data-hash']=''
        self.loginData['uuid_']=self.uuid
        self.loginData['signature_']=self.signature_
        self.loginData['userId_']=self.userId_
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
    def partslistinit(self):
        whitelist=[8420,8400,8380]
        a=['IUserParts','IUserPartsStatusSub']
        rev0=self.GetUserData(a)
        rev=json.loads(rev0.userDataJson_[a[0]])
        print(len(rev))
        parts_dic={}
        for line in rev:
            # print line
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
    def partslist_xx(self):
        parts_dic = self.partslistinit()
        xxlist={}
        for part in parts_dic:
            if parts_dic[part]['level']==15:
                xxlist[part]=parts_dic[part]
        # print xxlist
        tosave =[]
        others = []
        for part in xxlist:
            if 'CRITICAL_ATTACK' in  parts_dic[part] and  'CRITICAL_RATIO'  in  parts_dic[part] and 'PT_ATTACK' in  parts_dic[part]:
                # totallv = parts_dic[part]['PT_ATTACK'][2]+parts_dic[part]['CRITICAL_ATTACK'][2]+parts_dic[part]['CRITICAL_RATIO'][2]
                totallv = parts_dic[part]['CRITICAL_ATTACK'][2]+parts_dic[part]['CRITICAL_RATIO'][2]
                tag='×'
                if (totallv>=6 and parts_dic[part]['CRITICAL_ATTACK'][2]>=4) or \
                 (parts_dic[part]['CRITICAL_ATTACK'][2]>=3 and parts_dic[part]['CRITICAL_RATIO'][2]>=3 ):
                    tag='√'
                    tosave.append(part)
                else:
                    others.append(part)
            else:
                others.append(part)
            # print totallv,'\t',parts_dic[part]['PT_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_RATIO'][2],'\t',tag
                
        todelete=[]
        for part in parts_dic:
            if part not in  tosave:
                todelete.append(part)
        print('to save',len(tosave))
        print('ttlv\tatk\tcriatk\tcriratio')
        for part in tosave:
            totallv = parts_dic[part]['CRITICAL_ATTACK'][2]+parts_dic[part]['CRITICAL_RATIO'][2]
            print(totallv,'\t',parts_dic[part]['PT_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_RATIO'][2],'\t')
        print('to delete',todelete)
        # for part in others:
        #     totallv = parts_dic[part]['CRITICAL_ATTACK'][2]+parts_dic[part]['CRITICAL_RATIO'][2]
        #     print totallv,'\t',parts_dic[part]['PT_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_ATTACK'][2],'\t',parts_dic[part]['CRITICAL_RATIO'][2],'\t'
        if input("are you sure? (y/n)") == "y":
            self.sellpbycon(todelete)
        pass
    def rprint(self,msg):
        print('\r',msg, end=' ')
        sys.stdout.flush()
    def partslist_for_xhjb(self): # 为了消耗金币
        parts_dic = self.partslistinit()
        # 属性过滤
        tosave = []
        todelete = []
        need=['PT_ATTACK','CRITICAL_ATTACK','CRITICAL_RATIO']
        for part in parts_dic:
            # print parts_dic[part]
            if ('PT_ATTACK' in parts_dic[part] and 'x' == parts_dic[part]['PT_ATTACK'][0]\
            and 'CRITICAL_ATTACK' in parts_dic[part] and 60 == parts_dic[part]['CRITICAL_ATTACK'][1]\
            and 'CRITICAL_RATIO' in parts_dic[part] and 50 == parts_dic[part]['CRITICAL_RATIO'][1]) \
            or parts_dic[part]['level']==15:
            # if  need[0] in parts_dic[part] and need[1] in parts_dic[part] and need[2] in parts_dic[part]:
                # print part,parts_dic[part]
                tosave.append(part)
            else:
                todelete.append(part)
            if parts_dic[part]['level']!=15:
                sc =0
                # try:  
                while sc<15-parts_dic[part]['level']:
                    sc+=self.enhance(part)
                    self.rprint(str(len(todelete))+'\t'+str(sc))
                self.rprint(str(len(todelete))+'ed')

            if len(todelete)>=20:
                self.sellpbycon(todelete)
                todelete=[]
        
    def partslist(self):
        parts_dic = self.partslistinit()
        # 属性过滤
        tosave = []
        need=['PT_ATTACK','CRITICAL_ATTACK','CRITICAL_RATIO']
        for part in parts_dic:
            # print parts_dic[part]
            # if (parts_dic[part].has_key('PT_ATTACK') and 'x' == parts_dic[part]['PT_ATTACK'][0]\
            # and parts_dic[part].has_key('CRITICAL_ATTACK') and 60 == parts_dic[part]['CRITICAL_ATTACK'][1]\
            # and parts_dic[part].has_key('CRITICAL_RATIO') and 50 == parts_dic[part]['CRITICAL_RATIO'][1] ) \
            # or parts_dic[part]['level']!=1:
            if parts_dic[part]['level']!=1: #sell all
            # if  need[0] in parts_dic[part] and need[1] in parts_dic[part] and need[2] in parts_dic[part]:
                # print part,parts_dic[part]
                tosave.append(part)
        # return
        print('to save',len(tosave))
        # rev=all_parts_dic
        todelete = []
        for line in parts_dic:
            # print line
            if line not in tosave : #and parts_dic[line]['level']==1
                todelete.append(line)
        # print 'to delete',todelete
        if len(todelete)>1:
            self.sellpbycon(todelete)
        

        #升级
        for line in tosave:
            sc =0
            # try:  
            while sc<15-parts_dic[line]['level']:
                sc+=self.enhance(line)
                # print '\r',sc,
            print('done', end=' ')
            sys.stdout.flush()

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
    def dohdck(self):
        times=1700
        roll=7
        i=50
        # times=int(sys.argv[3])
        # roll=int(sys.argv[2])
        try:
            while i>0:
                self.GachaService_Draw(306000+roll,306000+roll,times)
                # print 'gacha done'
                self.GachaService_ResetBoxGachaRequest(306000+roll)
                i-=1
        except:
            print('no more ticket')
        
        return
    def domyac(self,cmd):
        global datahash
        self.initHeaders()
        self.uuid="06fde8db-b773-4976-bec5-83c4dfaddc38"
        self.terminalId_ =   "1A4AA2E5-1419-4EC6-9A4B-153F0CC5E3FE"
        self.signature_= "3cJsXeZ9aNInpvZ8YBdk1TvJ3nD9g8oc1g3gXupqxsk="
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('api.app.nierreincarnation.jp:443',self.creds)
        self.userId_='1649394160118177959'
        # self.Auth()
        self.mau()
        # self.GetLatestMasterDataVersion()
        if datahash=='':
            datahash=self.GetLatestMasterDataVersion()
        # print 'datahash',datahash
        self.meta['x-apb-master-data-hash']=datahash
        self.GetUserDataName()
        # self.GameStart()
        
        if cmd=='fl': #first login
            self.req_hex('/apb.api.data.DataService/GetUserData',open('enc_in_3').read().encode('hex'))
            return
        self.getuser()
        self.CheckBeforeGamePlay()
        self.LoginBonusService_ReceiveStamp()

        if cmd=='af':
            self.GetFriendRequestList()
            i=0
            ilen=len(self.my_friend_request)
            # print '\nmfr',self.my_friend_request
            for f in self.my_friend_request:
                i+=1
                showjd(i,ilen)
                self.AcceptFriendRequest(f)
            self.GetFriendList()
            # print '\nmfts', self.my_friend_tosend
            i=0
            ilen=len(self.my_friend_tosend)
            for f in self.my_friend_tosend:
                i+=1
                showjd(i,ilen)
                self.CheerFriend(f)
        elif cmd=='sw': #清理未锁定的装备
            if 0!=self.GiftService_GetGiftList():
                self.GiftService_ReceiveGift()
            a='IUserParts'
            rev=self.GetUserData([a])
            # print rev
            rev=json.loads(rev.userDataJson_[a])
            # print rev
            print(len(rev))
            # print rev[0]
            todelete=[]
            count=0
            for parts in rev:
                if parts['isProtected']==False and int(parts['level'])==1:
                    print(parts,parts['level'])
                    todelete.append(str(parts['userPartsUuid']))
                    count+=1
                if count>=10:
                    print(todelete)
                    self.sellparts(todelete)        
                    count=0
                    todelete=[]
            print(todelete)
            self.sellparts(todelete)        
                # print parts
        elif cmd=='sp':
            while 1:
                self.partslist()
                # self.partslist_for_xhjb()
                # self.req_hex('/apb.api.material.MaterialService/Sell','0a0808c19a0c10b9ef010a0808a18d0610a0fa010a0708c29a0c10f6520a0708a28d0610b059')    
                self.dohdck()
                self.cleanmail()
                if len(self.pre_list)==0:
                    return
        elif cmd=='sp1': #详细过滤
            self.partslist_xx()
        elif cmd=='mcl': # 卖材料
            self.req_hex('/apb.api.material.MaterialService/Sell','0a0808c19a0c10b9ef010a0808a18d0610a0fa010a0708c29a0c10f6520a0708a28d0610b059')
        elif cmd=='cf':
            self.GetFriendList()
            i=0
            ilen=len(self.my_friend_tosend)
            for f in self.my_friend_tosend:
                i+=1
                showjd(i,ilen)
                self.CheerFriend(f)
        elif cmd=='df':
            self.GetFriendList()
            i=0
            ilen=len(self.my_friend)
            for f in self.my_friend:
                i+=1
                showjd(i,ilen)
                self.DeleteFriendRequest(f)
            self.GetFriendRequestList()
            i=0
            ilen=len(self.my_friend_request)
            for f in self.my_friend_request:
                i+=1
                showjd(i,ilen)
                self.DeclineFriendRequest(f)
        elif cmd=='rf':
            self.GetFriendList()
            i=0
            ilen=len(self.my_friend_toreceive)
            # print '\nmftr',self.my_friend_toreceive
            for f in self.my_friend_toreceive:
                i+=1
                showjd(i,ilen)
                self.ReceiveCheer(f)
                self.DeleteFriendRequest(f)
            self.GetFriendRequestList()
            i=0
            ilen=len(self.my_friend_request)
            for f in self.my_friend_request:
                i+=1
                showjd(i,ilen)
                self.DeclineFriendRequest(f)
            self.getuser()
        elif cmd=='ts':
            print(self.stam)
            self.StartExplore(1)
            # time.sleep(100)
            self.FinishExplore(1)
            self.getuser()
            print(self.stam)
            # /apb.api.explore.ExploreService/StartExplore
            # /apb.api.explore.ExploreService/FinishExplore
        elif cmd=='tsq':
            print(self.stam)
            while 1:
                self.StartExplore(1,2001)
                # time.sleep(100)
                self.FinishExplore(1)
                self.getuser()
                print(self.stam)
        elif cmd=='m':
            self.cleanmail()
        elif cmd=='ck':
            i=1
            while i<40:
                i+=1
                self.GachaService_Draw(46,1,1)
        elif cmd=='zack':
            self.GachaService_Draw(209,209,1000)
        elif cmd=='hdck':
            times=1700
            roll=7
            # times=int(sys.argv[3])
            # roll=int(sys.argv[2])
            try:
                while 1:
                    self.GachaService_Draw(301000+roll,301000+roll,times)
                    print('gacha done')
                    self.GachaService_ResetBoxGachaRequest(301000+roll)
            except:
                print('no more ticket')
            
            return

        elif cmd=='hdckcz':
            roll=int(sys.argv[2])
            try:
                self.GachaService_ResetBoxGachaRequest(306000+roll)
                print('reset done')
            except:
                print('reset fail')
        elif cmd=='ga':
            # self.showgachaleft()
            self.GachaService_Draw(300007,300007,1)
        elif cmd=='jqck':
            # self.showgachaleft()
            print('9章-10,新章朝晖-14')
            target=200+int(sys.argv[2])
            times=int(sys.argv[3])
            self.GachaService_Draw(target,target,times)
        elif cmd=='mrdc': #每日剧情单抽
            self.req_hex('/apb.api.gacha.GachaService/Draw','08d50110d5011801')

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
                        times=self.stam/stamcost-1
                    else:
                        times=100000
                while times>0:
                    if -1==qfun(fnstep):
                        return
                    print('done '+sys.argv[2]+',',times,'left.')
                    times-=1
            self.getuser()
            print(self.stam)
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
                                            print('no drop, try next',i,total)
                                        else:
                                            print('get')
                                            return
                                        i+=1
                                        total+=1
                                self.getuser()
                                if self.stam<30:
                                    self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171055')
                                self.getuser()
                            

        elif cmd=='pvp':
            while 1:
                self.dopvp()
                print('done pvp')
        elif cmd=='qn':
            target=sys.argv[2]
            a1=99005
            a2=110095
            a3=3
            self.QuestService_StartEventQuest(a1,a2,a3)
            self.QuestService_FinishEventQuest(a1,a2)
            print('done qn')
        elif cmd=='sb':
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
        elif cmd=='sr':
            self.req_hex('/apb.api.shop.ShopService/RefreshUserData','0801')
            self.getuser()
            print(self.gold)
        elif cmd=='tly0': #体力药小
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171025')
            self.getuser()
            print(self.stam)
        elif cmd=='tly1': #体力药小
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08b9171055')
            self.getuser()
            print(self.stam)
        elif cmd=='tly2': #体力药中
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08ba17100a')
            self.getuser()
            print(self.stam)
        elif cmd=='tly3': #体力药大
            self.req_hex('/apb.api.consumableitem.ConsumableItemService/UseEffectItem','08bb171005')
            self.getuser()
            print(self.stam)
        elif cmd=='qh':
            self.req_hex('/apb.api.weapon.WeaponService/EnhanceByMaterial','0a2462313965303337362d646536302d343565332d383839332d623334386237393561346333120608c39a0c1001')
        elif cmd=='mrck':
            galist=['080510ad021801','08d2860310ad021801','08d3860310ad021801','08d4860310ad021801','08d5860310ad021801','08d6860310ad021801','08d8860310ae021801']
            for ga in galist:
                try:
                    print('do',ga)
                    self.req_hex('/apb.api.gacha.GachaService/Draw',ga)    
                    print('done',ga)
                except:
                    print('error',ga)
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','080510ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d2860310ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d3860310ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d4860310ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d5860310ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d6860310ad021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d7860310ae021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d8860310ae021801')
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','08d8860310ae021801')
            # print self.GachaService_Draw(1,301,1)
            pass
        elif cmd=='dc':
            print(self.req_hex('/apb.api.gacha.GachaService/Draw','08d8860310ae021801'))
            # print self.req_hex('/apb.api.gacha.GachaService/Draw','086310ad021801')
            # return
            # i=60001
            # while i<60010:
            #     try :
            #         print i
            #         self.getGacha([i])
            #         i+=1
            #     except:
            #         print 'error',i
            #         i+=1
            # bbb=pb.GetGachaRequest()
            # da= self.req_hex('/apb.api.gacha.GachaService/GetGacha','0a03d18603')
            # aaa=pb.GetGachaResponse()
            # aaa.ParseFromString(da)
            # print aaa
            # i=0
            # while i<10:
            #     print self.req_hex('/apb.api.gacha.GachaService/Draw','084e10011801')
            #     i+=1
        elif cmd=='tf': #讨伐
            jsq=json.loads(open('battlereq/config').read())
            # target=sys.argv[2]
            # isfound=0
            for q in jsq:
                if q['ftype']==100:
                    fnstep=q['fnstep']
                    self.dotf(fnstep)

            
            
        elif cmd=='pb': #跑步
            c=pb.CageMeasurableValues(runningDistanceMeters_=1000000,mamaTappedCount_=150)
            body=pb.GetMamaBannerRequest(c=c).SerializeToString()
            self.req_hex('/apb.api.mission.MissionService/UpdateMissionProgress',body.encode('hex'))
        elif cmd=='rw': #任务
            self.req_hex('/apb.api.mission.MissionService/ReceiveMissionRewardsById','0a0615161718191a')
            # self.req_hex('/apb.api.mission.MissionService/ReceiveMissionRewardsById','0a0ee920ea20eb20ec20ed20f020ee20')
        
        self.getuser()
        print('stam:', self.stam)
    def dotf(self,fnstep):
        if len(fnstep)==5:
            # self.req_binq('/apb.api.quest.QuestService/FinishEventQuest',fnstep[7][0],fnstep[7][1])
            self.req_binq('/apb.api.bighunt.BigHuntService/StartBigHuntQuest',fnstep[0][0],fnstep[0][1])
            self.req_binq('/apb.api.bighunt.BigHuntService/SaveBigHuntBattleInfo',fnstep[1][0],fnstep[1][1])
            self.req_binq('/apb.api.bighunt.BigHuntService/SaveBigHuntBattleInfo',fnstep[2][0],fnstep[2][1])
            self.req_binq('/apb.api.bighunt.BigHuntService/SaveBigHuntBattleInfo',fnstep[3][0],fnstep[3][1])
            self.req_binq('/apb.api.bighunt.BigHuntService/FinishBigHuntQuest',fnstep[4][0],fnstep[4][1])
            return 0
    def dopvp(self):
        pid=self.PvpService_GetMatchingList()
        self.PvpService_StartBattle(pid)
        self.PvpService_FinishBattle(pid)
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

    def getdrop(self,dp):
        for a in dp.battleDropReward_:
            # if a.battleDropEffectId_>=2:
            # print a.battleDropEffectId_,
            if a.battleDropEffectId_==3:
                print('hit')
                return 1
        # print 't:',len(dp.battleDropReward_)
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
                lastreq=open('battlereq/'+str(fnstep[7][0])).read()
                aaa=pb.FinishEventQuestRequest()
                aaa.ParseFromString(lastreq)
                aaa.isRetired_=True
                open('battlereq/tmp_last','wb').write(aaa.SerializeToString())
                # print aaa.SerializeToString().encode('hex')
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
    def doquickregist(self,num):
        global datahash
        self.initHeaders()
        self.uuid =  str(uuid.uuid4())
        self.terminalId_ =   "00000000-0000-0000-0000-000000000000"
        self.playername='z'+str(num)
        self.advertisingId_=str(uuid.uuid4()).upper()
        self.token='jnPvbX'
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('api.app.nierreincarnation.jp:443',self.creds)
        self.RegisterUser()
        self.Auth()
        if datahash=='':
            datahash=self.GetLatestMasterDataVersion()
        self.meta['x-apb-master-data-hash']=datahash
        # self.meta['x-apb-master-data-hash']='prd/20210311144430'
        # self.SetUserName()
        # self.GameStart()
        # self.CheckBeforeGamePlay()
        self.encyjm()
        self.SendFriendRequest(g_friend_list[0])
        return
    def showgachaleft(self):
        body={
    "commonRequest": {
        "appVersion": "1.1.0",
        "language": "ChineseSimplified",
        "osType": "1",
        "osVersion": "iOS 13.5",
        "deviceName": "iPhone12,5",
        "requestDatetime": int(str(int(time.time()*1000))),
        "requestId": 1,
        "sessionKey": self.sessionKey_,
        "userIdString": "1649394160118177959",
        "platformType": "1",
        "token": 'qmSFp8',
    },
    "gachaId": "300007"
}
        url='https://api-web.app.nierreincarnation.jp/api/gacha/odds'
        hd={
#         'accept': 'application/json, text/plain, */*',
# 'content-type': 'application/json; charset=utf-8',
# 'origin': 'https://web.app.nierreincarnation.jp',
# 'accept-language': 'zh-cn',
# 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
# 'accept-encoding':'gzip, deflate, br',
# 'referer':'https://web.app.nierreincarnation.jp/web/gacha/box?gachaId=300001&gachaId=300002&gachaId=300003&gachaId=300004&gachaId=300005&gachaId=300006&gachaId=300007&nowPlayingId=300007&userId=1649394160118177959&playerId=211262187909&sessionKey='+self.sessionKey_+'&appVersion=1.1.0&language=ChineseSimplified&osVersion=iOS%2013.5&deviceName=iPhone12,5&serverAddress=api.app.nierreincarnation.jp&token=qmSFp8&osType=1&platformType=1',
'accept': '*/*',
'origin': 'https://web.app.nierreincarnation.jp',
'access-control-request-method': 'POST',
'accept-language': 'zh-cn',
'access-control-request-headers': 'content-type',
'accept-encoding': 'gzip, deflate, br',
'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
'content-length':0,
'referer':'https://web.app.nierreincarnation.jp/web/gacha/box?gachaId=300001&gachaId=300002&gachaId=300003&gachaId=300004&gachaId=300005&gachaId=300006&gachaId=300007&nowPlayingId=300007&userId=1649394160118177959&playerId=211262187909&sessionKey='+self.sessionKey_+'&appVersion=1.1.0&language=ChineseSimplified&osVersion=iOS%2013.5&deviceName=iPhone12,5&serverAddress=api.app.nierreincarnation.jp&token=qmSFp8&osType=1&platformType=1',
}
        rev=self.options(url,'',hd,'')
        # rev=self.post(url,'',hd,str(json.dumps(body,separators=(',',':'))))
        print(rev)
    def PostData(self, url,path,hd,data):
        # print url,path
        if self.printlog==1 and self.printlogreq==1:
            print('>',url+path)
            print('>',hd)
            print('>',data)
        fullurl = url+path
        st = Storage()
        c = pycurl.Curl()
        hdlist=[]
        for h in hd:
            hdlist.append(str(h)+':'+str(hd[h]))
        c.setopt(pycurl.WRITEFUNCTION, st.storeBody)
        c.setopt(pycurl.HEADERFUNCTION, st.storeHeader)
        c.setopt(pycurl.POSTFIELDS,  data)
        c.setopt(pycurl.URL, fullurl)
        c.setopt(pycurl.HTTPHEADER,  hdlist)
        c.perform()
        status_code = c.getinfo(pycurl.HTTP_CODE) 
        resBody=st.loadBody()
        resHeader=st.loadHeader()
        if self.printlog==1 and self.printlogres==1:
            print('<',url+path,status_code)
            # print '<',resHeader
            # print '<',resBody
        self.refreshHeader(resHeader)
        return resBody
    def start(self,isGacha,num):

        self.initHeaders()
        self.uuid =  str(uuid.uuid4())
        self.terminalId_ =   "00000000-0000-0000-0000-000000000000"
        self.playername='z'+str(num)
        # print self.playername
        self.advertisingId_=str(uuid.uuid4()).upper()
        self.token='jnPvbX'
        
        
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('api.app.nierreincarnation.jp:443',self.creds)
        
        self.RegisterUser()
        self.Auth()
        self.GetLatestMasterDataVersion()
        # self.GetUserDataName()
        # self.GetUserData()
        # time.sleep(5)
        self.SetUserName()

        self.GameStart()
        self.CheckBeforeGamePlay()
        
        self.getuser()
        # self.encyjm()
        # self.SendFriendRequest(g_friend_list[0])
        # return
        # self.CompensationServiceReceive()
        self.QuestService_UpdateMainFlowSceneProgress(2)
        # time.sleep(1)

        self.QuestService_StartMainQuest(1)
        self.QuestService_UpdateMainQuestSceneProgress(2)
        self.QuestService_UpdateMainQuestSceneProgress(3)
        self.QuestService_UpdateMainQuestSceneProgress(4)
        self.QuestService_UpdateMainQuestSceneProgress(5)
        self.QuestService_UpdateMainQuestSceneProgress(6)
        self.QuestService_UpdateMainQuestSceneProgress(7)
        # time.sleep(5)
        self.QuestService_FinishMainQuest(1)
        self.QuestService_UpdateMainFlowSceneProgress(8)

        self.QuestService_UpdateMainFlowSceneProgress(9)
        self.QuestService_StartMainQuest(2)
        self.QuestService_UpdateMainQuestSceneProgress(10)
        self.QuestService_UpdateMainQuestSceneProgress(11)
        # start wave
        self.TutorialService_SetTutorialProgressRequest(4,10)
        # self.BattleService_FinishWave()

        self.QuestService_UpdateMainQuestSceneProgress(12)
        self.QuestService_UpdateMainQuestSceneProgress(13)
        self.QuestService_FinishMainQuest(2)
        self.QuestService_UpdateMainFlowSceneProgress(14)
        self.QuestService_UpdateMainFlowSceneProgress(17)
        self.QuestService_UpdateMainFlowSceneProgress(18)
        self.QuestService_StartMainQuest(5)
        self.QuestService_UpdateMainQuestSceneProgress(19)
        self.QuestService_UpdateMainQuestSceneProgress(20)
        # self.BattleService_FinishWave()
        self.QuestService_UpdateMainQuestSceneProgress(21)
        self.QuestService_UpdateMainQuestSceneProgress(22)
        self.QuestService_FinishMainQuest(5)
        self.QuestService_UpdateMainFlowSceneProgress(23)
        self.QuestService_UpdateMainFlowSceneProgress(26)
        self.QuestService_UpdateMainFlowSceneProgress(27)
        self.QuestService_StartMainQuest(8)
        self.QuestService_UpdateMainQuestSceneProgress(28)
        self.QuestService_UpdateMainQuestSceneProgress(29)
        # self.BattleService_FinishWave()
        self.QuestService_UpdateMainQuestSceneProgress(30)
        self.QuestService_UpdateMainQuestSceneProgress(31)
        
        self.QuestService_FinishMainQuest(8)
        # self.QuestService_UpdateMainQuestSceneProgress(32)
        self.QuestService_UpdateMainFlowSceneProgress(0x23)
        self.QuestService_UpdateMainFlowSceneProgress(0x24)
        self.QuestService_StartMainQuest(11)
        self.QuestService_UpdateMainQuestSceneProgress(0x25)
        self.QuestService_UpdateMainQuestSceneProgress(0x26)
        # self.BattleService_FinishWave()
        self.QuestService_UpdateMainQuestSceneProgress(0x27)
        self.QuestService_UpdateMainQuestSceneProgress(0x28)
        self.QuestService_FinishMainQuest(11)
        self.QuestService_UpdateMainFlowSceneProgress(0x29)
        self.QuestService_UpdateMainFlowSceneProgress(0x2a)
        # 
        # 
        # return
        self.TutorialService_SetTutorialProgressRequest(2,10)
        # self.TutorialService_SetTutorialProgressRequest(3,20)
        # self.TutorialService_SetTutorialProgressRequest(3,30)
        self.LoginBonusService_ReceiveStamp()
        self.GiftService_GetGiftList()
        self.GiftService_ReceiveGift()
        self.MissionService_ReceiveMissionRewardsById([201,210001,350001,350002,350003,360001,11,12,200001,210002,220001,230001,240001,250001,260001,270001,280001,290001,350004,360002,370001,400001,410001,420001,430001])
        self.getuser()
        # print self.gold,self.my_slist
        while self.gold>=3000:
            self.GachaService_Draw(2,2,1)
            self.gold-=3000
        while self.gold>=300:
            self.GachaService_Draw(2,1,1)
            self.gold-=300
        self.getuser()
        # print self.my_slist
        # print self.my_chara
        self.encyjm()
        # if 350011 in self.my_slist and 310081 in self.my_slist:
        #     print self.yjm
        # print 'done'
        print(self.yjm)
        # a=self.Auth()
        # print a
    def encyjm(self):
        da=str(self.uuid)+' '+str(self.signature_)+' '+str(self.userId_)
        # da='ABAA-370-060-126 224c7a0e381e5b9f5af0082d447cddeb07fb56562f1094822a89702960d48a35 KPPJ6XWKAN'
        key='1231231231231231'
        # self.aes_128_ecb_enc(self.view_id+' '+self.auth_token+' '+self.save_id)
        self.yjm= base64.b64encode(self.aes_128_ecb_enc(da,key))
    def getusermission(self):
        rev=self.GetUserData(["IUserLoginBonus","IUserLogin","IUserSetting","IUserMainQuestMainFlowStatus","IUserWeapon","IUser","IUserCostume","IUserWeaponNote","IUserStatus","IUserQuestMission","IUserCageOrnamentReward","IUserTutorialProgress","IUserPortalCageStatus","IUserCostumeActiveSkill","IUserExplore","IUserPartsGroupNote","IUserShopItem","IUserDokan","IUserQuestAutoOrbit","IUserImportantItem","IUserDeckCharacter","IUserConsumableItem","IUserWeaponAbility","IUserParts","IUserMainQuestProgressStatus","IUserGem","IUserQuest","IUserDeckTypeNote","IUserPvpDefenseDeck","IUserExtraQuestProgressStatus","IUserMission","IUserShopReplaceableLineup","IUserContentsStory","IUserEventQuestProgressStatus","IUserProfile","IUserNaviCutIn","IUserShopReplaceable","IUserCharacter"])
        print(rev)
        return
        rev=json.loads(rev.userDataJson_['IUserMission'])
        print(rev[0])
        for a in rev:
            print(a['missionId'],a['progressValue'],a['missionProgressStatusType'],time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(a['startDatetime']/1000)),time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(a['clearDatetime']/1000)))
        # rev=self.GetUserData(["IUserMissionTable"])
# 
    def getuser(self):
        rev=self.GetUserData(["IUserGem","IUser","IUserStatus","IUserEventQuestProgressStatus","IUserMainQuestProgressStatus"])
        # rev=self.req_hex('/apb.api.data.DataService/GetUserData','0a0f49557365724c6f67696e426f6e75730a0a49557365724c6f67696e0a0949557365724465636b0a1349557365724465636b506172747347726f75700a0c495573657253657474696e670a0e4955736572436f6d70616e696f6e0a13495573657250617274735374617475735375620a104955736572576561706f6e536b696c6c0a1c49557365724d61696e51756573744d61696e466c6f775374617475730a0b4955736572576561706f6e0a0549557365720a0c4955736572436f7374756d650a0f4955736572576561706f6e4e6f74650a0b49557365725374617475730a11495573657251756573744d697373696f6e0a174955736572436167654f726e616d656e745265776172640a1549557365725475746f7269616c50726f67726573730a154955736572506f7274616c436167655374617475730a174955736572436f7374756d65416374697665536b696c6c0a1149557365724578706c6f726553636f72650a104955736572576561706f6e53746f72790a1749557365724465636b537562576561706f6e47726f75700a0c49557365724578706c6f72650a134955736572506172747347726f75704e6f74650a0d495573657253686f704974656d0a0a4955736572446f6b616e0a13495573657251756573744175746f4f726269740a124955736572496d706f7274616e744974656d0a1249557365724465636b4368617261637465720a134955736572436f6e73756d61626c654974656d0a124955736572576561706f6e4162696c6974790a0a495573657250617274730a1c49557365724d61696e517565737450726f67726573735374617475730a0d49557365724d6174657269616c0a08495573657247656d0a0a495573657251756573740a1149557365724465636b547970654e6f74650a134955736572507670446566656e73654465636b0a1d49557365724578747261517565737450726f67726573735374617475730a0c49557365724d697373696f6e0a1a495573657253686f705265706c61636561626c654c696e6575700a124955736572436f6e74656e747353746f72790a1d49557365724576656e74517565737450726f67726573735374617475730a0c495573657250726f66696c650a0e49557365724e617669437574496e0a14495573657253686f705265706c61636561626c650a0e49557365724368617261637465720a0e4955736572507670537461747573')
        # rev=pb.UserDataGetResponse.FromString(rev)
        # for a in rev.userDataJson_:
        #     print a
        #     if a=='IUserCharacter':
        #         print rev.userDataJson_[a]
                # print a.value
        #     #     self.gold= int(json.loads(a.value)[0]['freeGem'])
        #     # if a.key=='IUserWeapon':
        #     #     self.my_slist=[]
        #     #     value = json.loads(a.value)
        #     #     for wea in value:
        #     #         self.my_slist.append(wea['weaponId'])
        # print rev.userDataJson_['IUserStatus']
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
            da='08c4850610bcdc0618013001c20c2834313962376461306133626636643766633763326363633165613063623239383139326566376166'.decode('hex')
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
            da='08fb4e10013001c20c2862333766663435646638653664313930373631653133656636633130326261663934353966643163'.decode('hex')
            aaa=pb.FinishMainQuestRequest()
            aaa.ParseFromString(da)
            # aaa.eventQuestChapterId_=eventQuestChapterId_
            aaa.questId_=questId_
            self.QuestService_FinishMainQuest_retired(aaa.SerializeToString()[:-40])
        else:
            print('no old mission to stop')
        # for wea in json.loads(rev.userDataJson_['IUserWeapon']):
        #     if str(wea['weaponId'])[0]=='3':
        #         self.my_slist.append(wea['weaponId'])
        # for chara in json.loads(rev.userDataJson_['IUserCharacter']):
        #     self.my_chara.append(chara['characterId'])
    def getGacha(self,gaidlist):
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.GetGachaRequest(gaid=gaidlist).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gacha.GachaService/GetGacha',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        print(rev)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.GetGachaResponse()
        aaa.ParseFromString(rev)
        print(aaa)
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

    def FinishExplore(self,exploreId_):
        # print '>call /apb.api.explore.ExploreService/FinishExplore'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.FinishExploreRequest(exploreId_= exploreId_,score_=107650).SerializeToString()+'c20c28'.decode('hex')+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        print(body.encode('hex'))
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.explore.ExploreService/FinishExplore',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.FinishExploreResponse()
        aaa.ParseFromString(rev)
        print(aaa)
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
    def GetOdds(self,pid):
        # print '>call /apb.api.friend.FriendService/SendFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.UpdateEventQuestSceneProgressReq(questSceneId_= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gacha.GachaService/GetOdds',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def SendFriendRequest(self,pid):
        # print '>call /apb.api.friend.FriendService/SendFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/SendFriendRequest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # try:
        #     resp,call=requester.with_call(body,metadata=metadata)
        #     rev=self.decb(resp)
        #     self.reloadmeta(call.trailing_metadata())
        # except:
        #     print 'error'
        
    def DeleteFriendRequest(self,pid):
        # print '>call /apb.api.friend.FriendService/DeleteFriend'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/DeleteFriend',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def DeclineFriendRequest(self,pid):
        # print '>call /apb.api.friend.FriendService/DeclineFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/DeclineFriendRequest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def AcceptFriendRequest(self,pid):
        # print '>call /apb.api.friend.FriendService/AcceptFriendRequest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/AcceptFriendRequest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def GetFriendRequestList(self):
        # print '>call /apb.api.friend.FriendService/GetFriendRequestList'
        metadata=self.refreshMetadata()
        # print metadata
        body=''
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/GetFriendRequestList',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.GetFriendRequestListResponse()
        aaa.ParseFromString(rev)
        self.my_friend_request=[]
        for a in aaa.friendUser_:
            self.my_friend_request.append(int(a.playerId_))
        # print self.my_friend_request
    def GetFriendList(self):
        # print '>call /apb.api.friend.FriendService/GetFriendList'
        metadata=self.refreshMetadata()
        # print metadata
        body='920300'.decode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/GetFriendList',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        aaa=pb.GetFriendListResponse()
        aaa.ParseFromString(rev)
        self.my_friend=[]
        self.my_friend_tosend=[]
        self.my_friend_toreceive=[]
        for a in aaa.friendUser_:
            self.my_friend.append(int(a.playerId_))
            # print a
            if a.cheerSent_==0:
                self.my_friend_tosend.append(int(a.playerId_))
            if a.cheerReceived_==1:
                self.my_friend_toreceive.append(int(a.playerId_))

        # print self.my_friend
    def ReceiveCheer(self,pid):
        # print '>call /apb.api.friend.FriendService/ReceiveCheer'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/ReceiveCheer',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def CheerFriend(self,pid):
        # print '>call /apb.api.friend.FriendService/CheerFriend'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SendFriendRequest(pid= pid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.friend.FriendService/CheerFriend',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_StartEventQuest(self,eventQuestChapterId_,qid,userDeckNumber=1):
        # print '>call QuestService_StartEventQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/StartEventQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_UpdateEventQuestSceneProgress(self,questSceneId_):
        # print '>call QuestService_UpdateEventQuestSceneProgress'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.UpdateEventQuestSceneProgressReq(questSceneId_= questSceneId_).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/UpdateEventQuestSceneProgress',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def req_binq(self,path,binq,needsign=0):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=open('battlereq/'+binq).read()
        if needsign==1:
            body=body[:-40]+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def req_hex(self,path,binq,needsign=0):
        # print '>call ',path,binq
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.StartEventQuest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,userDeckNumber_=userDeckNumber).SerializeToString()
        body=binq.decode('hex')
        if needsign==1:
            body=body[:-40]+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary(path,request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        return rev
    def QuestService_FinishMainQuest_retired(self,aaa):
        # print '>call QuestService/FinishMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.FinishMainQuestRequest(questId_=qid,isMainFlow_=isMainFlow,storySkipType_=1,isRetired_=0)
        # print body
        # body = body.SerializeToString()+self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=aaa+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
    def QuestService_FinishEventQuest_retired(self,aaa):
        # print '>call QuestService_FinishEventQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=aaa+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        print(body.encode('hex'))
        body=self.encb(body)

        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishEventQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_FinishEventQuest(self,eventQuestChapterId_,qid):
        # print '>call QuestService_FinishEventQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.FinishEventQuestRequest(questId_= qid,eventQuestChapterId_= eventQuestChapterId_,storySkipType_=1).SerializeToString()+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishEventQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def encb(self,da):
        enckey='1234567890ABCDEF'
        enciv='it8bAjktKdFIBYtU'
        return self.rijndael_enc(da,enckey,enciv)
    def decb(self,da):
        # key='6Cb01321EE5e6bBe'
        # iv='EfcAef4CAe5f6DaA'
        enckey='1234567890ABCDEF'
        enciv='it8bAjktKdFIBYtU'
        return self.rijndael_dec(da,enckey,enciv)
    def ruencb(self,da):
        # print da
        return da
        # pass
    def redecb(self,da):
        # print da
        return da
    def refreshMetadata(self):
        self.meta['x-apb-request-datetime']=str(int(time.time()))
        self.meta['x-apb-device-id']=str(uuid.uuid4()).upper()
        self.meta['x-apb-request-id']=str(random.random()*1000000000)[:9]+str(random.random()*10000000000)[:10]
        return tuple( (x,self.meta[x]) for x in self.meta)
    def reloadmeta(self,meta):
        # print meta
        for a in meta:
            if a.key=='x-apb-token':
                self.meta['x-apb-token']=a.value
    def RegisterUser(self):
        stub = func.UserServiceStub(self.channel)
        # print '>call RegisterUser'
        # tt=str(int(time.time()))
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.RegisterUserRequest(uuid_=self.uuid,terminalId_=self.terminalId_,registerSignature_=self.hmac_sha256(self.uuid+self.terminalId_,'qzn8MLVdfXEcNVuqEirJbogd'))
        body=body.SerializeToString()
        body=self.encb(body)
        reqRegisterUser = self.channel.unary_unary('/apb.api.user.UserService/RegisterUser',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=reqRegisterUser.with_call(body,metadata=metadata)
        # for a in resp:
        #     print '-------'
        #     print a
        self.reloadmeta(call.trailing_metadata())
        # print call
        # print call.trailing_metadata()
        # print dir(call)
        # for a in call.initial_metadata():
        #     print a.key,':',a.value
        rev=self.decb(resp)
        revj=pb.RegisterUserResponse.FromString(rev)
        # print revj
        self.userId_=str(revj.userId_)
        self.signature_=str(revj.signature_)
    def Auth(self):
        # print '>call Auth'
        metadata=self.refreshMetadata()
        body=pb.AuthUserRequest(uuid_=self.uuid,signature_=self.signature_,advertisingId_=self.terminalId_, tr_="{\"tr\":[{\"ti\":\"lr\",\"bo\":\"\"},{\"ti\":\"ijb\",\"bo\":\"True\"},{\"ti\":\"hig\",\"bo\":\"False\"},{\"ti\":\"acs\",\"bo\":\"\"},{\"ti\":\"per\",\"bo\":\"False\"},{\"ti\":\"imu\",\"bo\":\"False\"},{\"ti\":\"ir\",\"bo\":\"False\"},{\"ti\":\"ia\",\"bo\":\"False\"},{\"ti\":\"ms\",\"bo\":\"System.String[]\"},{\"ti\":\"ics\",\"bo\":\"\"}]}")
        body=body.SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.user.UserService/Auth',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.AuthUserResponse.FromString(rev)
        # print revj
        self.sessionKey_=str(revj.sessionKey_)
        self.meta['x-apb-user-id']= self.userId_
        self.meta['x-apb-session-key']= self.sessionKey_
        # self.meta['x-apb-master-data-version']= '0'
        self.meta['x-apb-master-data-hash']=''
        self.loginData['uuid_']=self.uuid
        self.loginData['signature_']=self.signature_
        self.loginData['userId_']=self.userId_
        return revj
    def SetUserName(self):
        # print '>call SetUserName'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.SetUserNameRequest(name=self.playername)
        body=body.SerializeToString()
        # print body.encode('hex')
        body=self.encb(body)
        # print body.encode('hex')
        requester = self.channel.unary_unary('/apb.api.user.UserService/SetUserName',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.differResponse.FromString(rev)
        # print revj
    def GameStart(self):
        # print '>call GameStart'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.GameStartReq()
        body=body.SerializeToString()
        # print body.encode('hex')
        body=self.encb(body)
        # print body.encode('hex')
        requester = self.channel.unary_unary('/apb.api.user.UserService/GameStart',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.differResponse.FromString(rev)
        # print revj
    def CheckBeforeGamePlay(self):
        # print '>call CheckBeforeGamePlay'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.CheckBeforeGamePlay()
        body=body.SerializeToString()
        # print body.encode('hex')
        body=self.encb(body)
        # print body.encode('hex')
        requester = self.channel.unary_unary('/apb.api.gameplay.GamePlayService/CheckBeforeGamePlay',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        revj=pb.differResponse.FromString(rev)
        # print revj
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
        # revj=pb.differResponse.FromString(rev)
        # print revj
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
        # print rev
    def CompensationServiceReceive(self):
        # print '>call CompensationServiceReceive'
        metadata=self.refreshMetadata()
        # print metadata
        body=''
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gift.GiftService/GetGiftNotReceiveCount',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
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
        # print rev
    def QuestService_StartMainQuest(self,qid,isMainFlow=True,userDeckNumber=1):
        # print '>call QuestService/StartMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.StartMainQuest(questId_= qid,isMainFlow_= isMainFlow,userDeckNumber_=userDeckNumber).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/StartMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        # try:
        resp,call=requester.with_call(body,metadata=metadata)
        # except grpc.RpcError as e:
        #     print (e.details())
        #     print e
        #     return 
        #     status_code = e.code()
        #     # should print `INVALID_ARGUMENT`
        #     print(status_code.name)
        #     # should print `(3, 'invalid argument')`
        #     print(status_code.value)
        #     # want to do some specific action based on the error?
        #     if grpc.StatusCode.INVALID_ARGUMENT == status_code:
        #         # do your stuff here
        #         pass
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
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
        # print rev
    def BattleService_FinishWave(self):
        # print '>call BattleService/FinishWave'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.intmessage(p1=p1va).SerializeToString()
        # body=self.encb(body)
        body=pb.FinishWaveRequest().SerializeToString()+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)
        body=''
        requester = self.channel.unary_unary('/apb.api.battle.BattleService/FinishWave',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
    def BattleService_StartWave(self):
        # print '>call BattleService/StartWave'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.intmessage(p1=p1va).SerializeToString()
        # body=self.encb(body)
        body=pb.FinishWaveRequest().SerializeToString()+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body=self.encb(body)
        body=''
        requester = self.channel.unary_unary('/apb.api.battle.BattleService/FinishWave',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
    def QuestService_FinishMainQuest(self,qid,isMainFlow=True):
        # print '>call QuestService/FinishMainQuest'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.FinishMainQuestRequest(questId_=qid,isMainFlow_=isMainFlow,storySkipType_=1,isRetired_=0)
        # print body
        # body = body.SerializeToString()+self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        body = ('08'+str("%02x"%qid)+'18013001c20c28').decode('hex')+ self.gensha1(self.meta['x-apb-user-id']+self.meta['x-apb-token'] )
        # print body.encode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.quest.QuestService/FinishMainQuest',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
        # print rev
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
        # print rev
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
        # print rev
    def GiftService_GetGiftList(self):
        # print '>call GiftService/GetGiftList'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.GetGiftListRequest(rewardKindType_=[1],expirationType_=1,getCount_=20).SerializeToString()
        body='0a010110013014'.decode('hex') # 所有
        # 0a070207040506080910013014  不包含金币
        body='0a070207040506080910013014'.decode('hex')
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

        # print len(self.pre_list)
        return revj
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
    def MissionService_ReceiveMissionRewardsById(self,mid):
        # print '>call MissionService/ReceiveMissionRewardsById'
        metadata=self.refreshMetadata()
        # print metadata
        body=pb.ReceiveMissionRewardsById(mid=mid).SerializeToString()
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.mission.MissionService/ReceiveMissionRewardsById',request_serializer=self.ruencb,response_deserializer=self.redecb)
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
        # print revj
    def GachaService_GetGachaList(self):
        # print '>call GachaService/GetGachaList'
        metadata=self.refreshMetadata()
        # print metadata
        # body=pb.DrawRequest(gachaId_=gachaId_,gachaPricePhaseId_=gachaPricePhaseId_,execCount_=execCount_).SerializeToString()
        body='0a0401020304'.decode('hex')
        body=self.encb(body)
        requester = self.channel.unary_unary('/apb.api.gacha.GachaService/GetGachaList',request_serializer=self.ruencb,response_deserializer=self.redecb)
        resp,call=requester.with_call(body,metadata=metadata)
        rev=self.decb(resp)
        self.reloadmeta(call.trailing_metadata())
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

    def relogin(self,row):
        self.acid=row[0]
        self.loginData=json.loads(row[1])

        self.initHeaders()
        self.secret_key=self.loginData['secret_key']
    def gensha256(self,data):
        import hashlib
        m2 = hashlib.sha256()
        m2.update(data)
        return m2.digest()
    def aes_128_ecb_dec(self,message,key):
        from Crypto.Cipher import AES
        cryptor = AES.new(key, AES.MODE_ECB)
        decd = cryptor.decrypt(message)
        decd = self.unpad(decd)
        return decd
    def aes_128_ecb_enc(self,message,key):
        from Crypto.Cipher import AES
        cryptor = AES.new(key, AES.MODE_ECB)
        encd = cryptor.encrypt(self.pad(message))
        return encd
    def rijndael_dec(self,todec,key,iv):
        import rijndael
        from rijndael.cipher.crypt import new
        from rijndael.cipher.blockcipher import MODE_CBC
        # iv = todec[0:16]
        # a = todec[16:]
        rjn = new(key, MODE_CBC, iv, blocksize=16)
        return self.unpad(rjn.decrypt(todec))
        # return rjn.decrypt(todec)

    def rijndael_enc(self,toenc,key,iv):
        import rijndael
        from rijndael.cipher.crypt import new
        from rijndael.cipher.blockcipher import MODE_CBC
        rjn = new(key, MODE_CBC, iv, blocksize=16)
        toenc = self.pad(toenc)
        return rjn.encrypt(toenc)
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
    def post(self,mainUrl,path,hd,body):
        # time.sleep(1)
        url=mainUrl+path


        if self.printlog==1 and self.printlogreq==1:
            print('+_url '+url, end=' ')
            print('+_hd',hd, end=' ')
            print('+_bd',body)
        https = urllib3.PoolManager()
        r = https.request('POST', url, body=body,headers=hd)
        
        if self.printlog==1 and self.printlogres==1:
            print(r.status)
            print('-_rb '+str(r.data))
            print('-_rh '+str(r.headers))
        self.refreshHeader(r.headers)
        return r.data
    def options(self,mainUrl,path,hd,body):
        # time.sleep(1)
        url=mainUrl+path


        if self.printlog==1 and self.printlogreq==1:
            print('+_url '+url, end=' ')
            print('+_hd',hd, end=' ')
            print('+_bd',body)
        https = urllib3.PoolManager()
        r = https.request('OPTIONS', url, body=body,headers=hd)
        
        if self.printlog==1 and self.printlogres==1:
            print(r.status)
            print('-_rb '+str(r.data))
            print('-_rh '+str(r.headers))
        self.refreshHeader(r.headers)
        return r.data
    def get(self,mainUrl,path,hd):
        # time.sleep(1)
        url=mainUrl+path
        if self.printlog==1 and self.printlogreq==1:
            print('+_url '+url, end=' ')
        https = urllib3.PoolManager()
        r = https.request('GET', url,headers=hd)
        if self.printlog==1 and self.printlogres==1:
            print(r.status)
            # print '-_rb '+str(r.data)
            # print '-_rh '+str(r.headers)
        self.refreshHeader(r.headers)
        return r.data

    def refreshHeader(self,headers):
        # if 'Set-Cookie' in headers:
            # self.gameHeaders['Cookie']=headers['Set-Cookie']
        # self.gameHeaders['Http-Req-Id']=int(time.time()*1000)
        return 0
 
    def random_str(self,min=6,max=12):
        from random import Random
        random = Random()
        randomlength=random.randint(min,max)
        str = ''
        chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
        length = len(chars) - 1
        for i in range(randomlength):
            str+=chars[random.randint(0, length)]
        return str
    def loadAc(self,yjm):
        # self.uuid =  str(uuid.uuid4()).upper()
        key='1231231231231231'
        yjm= base64.b64decode(yjm)
        acdata=self.aes_128_ecb_dec(yjm,key).split(' ')
        # print acdata
        self.initHeaders()
        self.uuid=acdata[0]
        self.signature_=acdata[1]
        self.userId_=acdata[2]
        self.terminalId_ =   "00000000-0000-0000-0000-000000000000"
        # self.playername=self.random_str()
        # self.advertisingId_=str(uuid.uuid4()).upper()
        self.creds = grpc.ssl_channel_credentials(open('roots.pem').read())
        self.channel = grpc.secure_channel('api.app.nierreincarnation.jp:443',self.creds)
        self.Auth()
        self.GetLatestMasterDataVersion()
        self.LoginBonusService_ReceiveStamp()
        # self.getuser()
        self.GetFriendList()
        return 0

import sys
def startNewAcByThreadNum(tn):
    threads = []
    for x in range(1,tn+1):
        t = threading.Thread(target=oneTask, name='worker',args=(tn,))
        # t = threading.Thread(target=oneTaskTest, name='worker',args=(isGacha,))
        threads.append(t)
        # print threads,t
    for x in threads:
        x.start()
        time.sleep(1)
    for x in threads:
        x.join()
def oneTask(tn):

        # addNewAcToFile(5)
    filep=open(acfile,'a')
    yy=''
    tt=tn*10
    num=0
    while num<10:
        k = reqfuncmjzj()
        k.start(1,tt)
        # yy+=k.yjm+'\n'
        tt-=1
        num+=1
        filep.write(k.yjm+'\n')
        print('done',tn,num)
    print('all done', tn)
        # time.sleep(30)

def showjd(i,ilen):
    sys.stdout.flush()
    percent = 100 * i / ilen
    sys.stdout.write(" >>%.1f"%percent)
    sys.stdout.write("%\r")
    sys.stdout.flush()

class acM:
    list_Instance=[]
    card_list={}
    limit=500
    def initAcFromFile(self):
        ac=open(acfile).read().split('\n')
        # print ac
        # p = Progress('loading', len(ac))
        # p.start()
        self.initAcFromList(ac)
    def initAcFromList(self,aclist):
        lim=0
        i=0
        ilen=len(aclist)
        for yjm in aclist:
            i+=1
            showjd(i,ilen)
            if len(yjm)>0:
                print('do',yjm)
                newIns = reqfuncmjzj()
                if 0==newIns.loadAc(yjm):
                    self.list_Instance.append(newIns)
                    for target in g_friend_list:
                        if int(target) not in newIns.my_friend:
                            # print 'SendFriendRequest',target,newIns.my_friend
                            newIns.SendFriendRequest(target)        
                    # newIns.GetFriendList()
                    for f in newIns.my_friend_tosend:
                        newIns.CheerFriend(f)
                        # newIns.ReceiveCheer(g_friend_list[0])
                    # newIns.GetFriendList()
                    for f in newIns.my_friend_toreceive:
                        newIns.ReceiveCheer(f)
            lim+=1
            if lim>=self.limit:
                return
    def step1(self,aclist):
        for yjm in aclist:
            i+=1
            showjd(i,ilen)
            if len(yjm)>0:
                print('do',yjm)
                newIns = reqfuncmjzj()
                newIns.dozbac('step1',yjm)
    def step2(self,aclist):
        for yjm in aclist:
            i+=1
            showjd(i,ilen)
            if len(yjm)>0:
                print('do',yjm)
                newIns = reqfuncmjzj()
                newIns.dozbac('step2',yjm)
    def step3(self,aclist):
        for yjm in aclist:
            i+=1
            showjd(i,ilen)
            if len(yjm)>0:
                print('do',yjm)
                newIns = reqfuncmjzj()
                newIns.dozbac('step3',yjm)
    
    def SendFriendRequest(self):
        for ins in self.list_Instance:
            for target in g_friend_list:
                if int(target) not in ins.my_friend:
                    # print 'SendFriendRequest',target,ins.my_friend
                    ins.SendFriendRequest(target)        
                    # ins.GetFriendList()
    def CheerFriend(self):
        for ins in self.list_Instance:
            ins.GetFriendList()
            for target in g_friend_list:
                ins.CheerFriend(target)

acfile='acListNew_nese_0225'
def addNewAcToFile(tt):
    filep=open(acfile,'a')
    ttnum=10000
    yy=''
    # tt=1
    while ttnum>0:
        k = reqfuncmjzj()
        k.start(1,tt)
        # yy+=k.yjm+'\n'
        tt-=1
        ttnum-=1
        filep.write(k.yjm+'\n')
# addNewAcToFile(200)



# if (sys.argv[1])=='my':
#     k = reqfuncmjzj()
#     k.domyac()
# elif (sys.argv[1])=='zb':
#     # if 
#     cmd =sys.argv[2]
#     if cmd == 'old': 
#         dbnum=(sys.argv[3])
#         acfile='acListNew_nese_'+dbnum
#         g_friend_list=[211262187909]
#         print '1. send stam to friend'
#         a=acM()
#         print '-----initAcFromFile-----'
#         a.initAcFromFile()
#         print '-----checkfriend-----'
#         # a.SendFriendRequest()
#         # if len(sys.argv)>3:
#         #     if str(sys.argv[3])=='cf':
#         #         a.CheerFriend(f)
#     elif cmd == 'new':
#         cmd2 = (sys.argv[3])
#         acfile='acListNew_nese_'+str(int(cmd2)-1)
#         print 'save to ',acfile
#         addNewAcToFile(int(cmd2)*100)

# zb old x
# my af
# zb old x
# my rf

# k=reqfuncmjzj()
# k.aa()
# sys.exit(0)



def dozbside(step,aclist):
    i=0
    ilen=len(aclist)
    for yjm in aclist:
        i+=1
        showjd(i,ilen)
        if len(yjm)>0:
            # print 'do',yjm
            newIns = reqfuncmjzj()
            newIns.dozbac(step,yjm)
def domyside(cmd):
    k = reqfuncmjzj()
    k.domyac(cmd)
    return k

def step1(ttcount):
    aclist=[]
    i=0
    ilen=ttcount
    tt=5000
    while i<ilen:
        i+=1
        tt-=1
        showjd(i,ilen)
        k = reqfuncmjzj()
        k.doquickregist(tt)
        aclist.append(k.yjm)
    return aclist
def step2(aclist):
    i=0
    ilen=len(aclist)
    for yjm in aclist:
        i+=1
        showjd(i,ilen)
        if len(yjm)>0:
            # print 'do',yjm
            newIns = reqfuncmjzj()
            newIns.dozbac('step2',yjm)
def step3(aclist):
    i=0
    ilen=len(aclist)
    for yjm in aclist:
        i+=1
        showjd(i,ilen)
        if len(yjm)>0:
            # print 'do',yjm
            newIns = reqfuncmjzj()
            newIns.dozbac('step3',yjm)



# if int(sys.argv[1])>0 and int(sys.argv[1]) <100:
# if sys.argv[1]=='n':
#     n = sys.argv[2]
#     g_friend_list=[211262187909]
#     # thisRun=int(sys.argv[1])
#     thisRun=1
#     while 1:    
#         ttcount=100
#         # thisRunList=[]
#         # toend=int((thisRun+1)*100)-1
#         # if toend>=len(acall):
#         #     toend=len(acall)
#         # tmplist=acall[int(thisRun*100):toend]
#         # exitthisrun=0
#         # for a in tmplist:
#         #     if a=='end':
#         #         exitthisrun=1
#         #         break
#         #     thisRunList.append(a)
#         print '#####start round ['+n+'-'+str(thisRun)+']#####'
#         print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
#         print '>1 df'
#         k=domyside('df')
#         if k.stam>980:
#             print '>980 exit'
#             sys.exit(0)
#         if k.stam>799:
#             # print 'stam over 800,exit. current round is', thisRun
#             # sys.exit(0)
#             ttcount = (999-k.stam)/2
#         print k.stam
#         print '>2 zb step1'
#         # dozbside('step1',thisRunList)
#         thisRunList=step1(ttcount)
        
#         print '>3 af'
#         k=domyside('af')
#         # if k.stam>=900:
#         #     print 'stam over 800,exit. current round is', thisRun
#         #     sys.exit(0)
#         print '\n',k.stam
        
#         print '>4 zb step2'
#         dozbside('step2',thisRunList)
        
#         print '>5 rf'
#         k=domyside('rf')
        
#         # print '>6 zb step3'
#         # dozbside('step3',thisRunList)
#         print '\n',k.stam


#         # print '#####start round'+str(thisRun)+'#####'
#         thisRun+=1
#         # if exitthisrun==1:
#         sys.exit(0)
# elif sys.argv[1]=='c':
#     k=reqfuncmjzj()
#     k.aa()
#     # k.partslist()
# else:
k=reqfuncmjzj()
k.domyac(sys.argv[1])
# if sys.argv[1]=='q':
#     k=reqfuncmjzj()
#     k.domyac('q')
# elif   sys.argv[1]=='qd':
#     k=reqfuncmjzj()
#     k.domyac('qd')
# elif   sys.argv[1]=='m':
#     k=reqfuncmjzj()
#     k.domyac('m')
# elif   sys.argv[1]=='zack':
#     k=reqfuncmjzj()
#     k.domyac('zack')
# elif   sys.argv[1]=='hdck':
#     k=reqfuncmjzj()
#     k.domyac('hdck')
# elif sys.argv[1]=='n':
#     addNewAcToFile(10000)
# else:
# acfile = 'acall'
# acall = open(acfile).read().split('\n')
# print 'total ac:',len(acall)
# yjm=acall[0]
# k=reqfuncmjzj()
# k.domyac('ts')
# sys.exit(0)
# print acall[0]



    



# arg1=''
# if len(sys.argv)>1:
#     if str(sys.argv[1])=='1':
#         while 1:
#             k = reqfuncmjzj()
#             k.start(1)
#             del k
#     elif str(sys.argv[1])=='my':
#         k = reqfuncmjzj()
#         k.domyac()
# else:
#     k = reqfuncmjzj()
#     k.aa()