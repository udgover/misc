#

# scrdec.c - Decoder for Microsoft Script Encoder
# Version 1.8
#
# COPYRIGHT:
# (c)2000-2005 MrBrownstone, mrbrownstone@ virtualconspiracy.com
# v1.8 Now correctly decodes characters 0x00-0x1F, thanks to 'Zed'
# v1.7 Bypassed new HTMLGuardian protection and added -dumb switch
#      to disable this
# v1.6 Added HTML Decode option (-htmldec)
# v1.5 Bypassed a cleaver trick defeating this tool
# v1.4 Some changes by Joe Steele to correct minor stuff
#
# DISCLAIMER:
# This program is for demonstrative and educational purposes only.
# Use of this program is at your own risk. The author cannot be held
# responsible if any laws are broken by use of this program.
#
# If you use or distribute this code, this message should be held
# intact. Also, any program based upon this code should display the
# copyright message and the disclaimer.


RawData =[0x64,0x37,0x69, 0x50,0x7E,0x2C, 0x22,0x5A,0x65, 0x4A,0x45,0x72, 
          0x61,0x3A,0x5B, 0x5E,0x79,0x66, 0x5D,0x59,0x75, 0x5B,0x27,0x4C, 
          0x42,0x76,0x45, 0x60,0x63,0x76, 0x23,0x62,0x2A, 0x65,0x4D,0x43, 
          0x5F,0x51,0x33, 0x7E,0x53,0x42, 0x4F,0x52,0x20, 0x52,0x20,0x63, 
          0x7A,0x26,0x4A, 0x21,0x54,0x5A, 0x46,0x71,0x38, 0x20,0x2B,0x79, 
          0x26,0x66,0x32, 0x63,0x2A,0x57, 0x2A,0x58,0x6C, 0x76,0x7F,0x2B, 
          0x47,0x7B,0x46, 0x25,0x30,0x52, 0x2C,0x31,0x4F, 0x29,0x6C,0x3D, 
          0x69,0x49,0x70, 0x3F,0x3F,0x3F, 0x27,0x78,0x7B, 0x3F,0x3F,0x3F, 
          0x67,0x5F,0x51, 0x3F,0x3F,0x3F, 0x62,0x29,0x7A, 0x41,0x24,0x7E, 
          0x5A,0x2F,0x3B, 0x66,0x39,0x47, 0x32,0x33,0x41, 0x73,0x6F,0x77, 
          0x4D,0x21,0x56, 0x43,0x75,0x5F, 0x71,0x28,0x26, 0x39,0x42,0x78, 
          0x7C,0x46,0x6E, 0x53,0x4A,0x64, 0x48,0x5C,0x74, 0x31,0x48,0x67, 
          0x72,0x36,0x7D, 0x6E,0x4B,0x68, 0x70,0x7D,0x35, 0x49,0x5D,0x22, 
          0x3F,0x6A,0x55, 0x4B,0x50,0x3A, 0x6A,0x69,0x60, 0x2E,0x23,0x6A, 
          0x7F,0x09,0x71, 0x28,0x70,0x6F, 0x35,0x65,0x49, 0x7D,0x74,0x5C, 
          0x24,0x2C,0x5D, 0x2D,0x77,0x27, 0x54,0x44,0x59, 0x37,0x3F,0x25, 
          0x7B,0x6D,0x7C, 0x3D,0x7C,0x23, 0x6C,0x43,0x6D, 0x34,0x38,0x28, 
          0x6D,0x5E,0x31, 0x4E,0x5B,0x39, 0x2B,0x6E,0x7F, 0x30,0x57,0x36, 
          0x6F,0x4C,0x54, 0x74,0x34,0x34, 0x6B,0x72,0x62, 0x4C,0x25,0x4E, 
          0x33,0x56,0x30, 0x56,0x73,0x5E, 0x3A,0x68,0x73, 0x78,0x55,0x09, 
          0x57,0x47,0x4B, 0x77,0x32,0x61, 0x3B,0x35,0x24, 0x44,0x2E,0x4D, 
          0x2F,0x64,0x6B, 0x59,0x4F,0x44, 0x45,0x3B,0x21, 0x5C,0x2D,0x37, 
          0x68,0x41,0x53, 0x36,0x61,0x58, 0x58,0x7A,0x48, 0x79,0x22,0x2E, 
          0x09,0x60,0x50, 0x75,0x6B,0x2D, 0x38,0x4E,0x29, 0x55,0x3D,0x3F,
          0x51,0x67,0x2f]

PickEncodings = [1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 
                 1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2, 
                 1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 
                 1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2]
                      

EntityMap = {"excl" : 33, "quot" : 34, "num" : 35, "dollar" : 36, "percent" : 37,
             "amp" : 38, "apos" : 39, "lpar" : 40, "rpar" : 41, "ast" : 42,
             "plus" : 43, "comma" : 44, "period" : 46, "colon" : 58, "semi" : 59,
             "lt" : 60, "equals" : 61, "gt" : 62, "quest" : 63, "commat" : 64,
             "lsqb" : 91, "rsqb" : 93, "lowbar" : 95, "lcub" : 123, "verbar" : 124,
             "rcub" : 125, "tilde" : 126}


class ScriptDecoder(object):
    STATE_INIT_COPY	 = 100
    STATE_COPY_INPUT	 = 101
    STATE_SKIP_ML	 = 102
    STATE_CHECKSUM	 = 103
    STATE_READLEN	 = 104
    STATE_DECODE	 = 105
    STATE_UNESCAPE	 = 106
    STATE_FLUSHING	 = 107
    STATE_DBCS		 = 108
    STATE_INIT_READLEN	 = 109
    STATE_URLENCODE_1	 = 110
    STATE_URLENCODE_2	 = 111
    STATE_WAIT_FOR_CLOSE = 112
    STATE_WAIT_FOR_OPEN  = 113
    STATE_HTMLENCODE     = 114


    def __init__(self, urlencoded=0, htmlencoded=0, verbose=0, smart=1, cp=0):
        self.__urlencoded = urlencoded
        self.__htmlencoded = htmlencoded
        self.__verbose = verbose
        self.__smart = smart
        self.__cp = cp
        self.__transformed = []
        for j in xrange(0, 3):
            self.__transformed.append([0 for i in xrange(0, 128)])
        self.__digits = [0 for i in xrange(0, 123)]
        self.__makeTrans()
        self.__makeDigits()
        self.__state_functions = {ScriptDecoder.STATE_INIT_COPY: self.__stateInitCopy,
                                  ScriptDecoder.STATE_WAIT_FOR_CLOSE: self.__stateWaitForClose,
                                  ScriptDecoder.STATE_WAIT_FOR_OPEN: self.__stateWaitForOpen,
                                  ScriptDecoder.STATE_COPY_INPUT: self.__stateCopyInput,
                                  ScriptDecoder.STATE_FLUSHING: self.__stateFlushing,
                                  ScriptDecoder.STATE_SKIP_ML: self.__stateSkipMl,
                                  ScriptDecoder.STATE_INIT_READLEN: self.__stateInitReadLen,
                                  ScriptDecoder.STATE_READLEN: self.__stateReadLen,
                                  ScriptDecoder.STATE_DECODE: self.__stateDecode,
                                  ScriptDecoder.STATE_DBCS: self.__stateDbcs,
                                  ScriptDecoder.STATE_UNESCAPE: self.__stateUnescape,
                                  ScriptDecoder.STATE_CHECKSUM: self.__stateChecksum,
                                  ScriptDecoder.STATE_URLENCODE_1: self.__stateUrlEncode1,
                                  ScriptDecoder.STATE_URLENCODE_2: self.__stateUrlEncode2,
                                  ScriptDecoder.STATE_HTMLENCODE: self.__stateHtmlEncode}
        self.resetStateMachine()


    def decodeStream(self, instream, outstream):
        inbuf = ""
        outbuf = ""


    def decodeBuffer(self, buff):
        out = ""
        self.__i = 0
        self.__buff = buff

        while self.__state:
            if self.__i == len(self.__buff):
                break
            if self.__urlencoded and self.__buff[self.__i] == '%':
                self.__ustate = self.__state
                self.__state = ScriptDecoder.STATE_URLENCODE_1
                self.__i += 1
                continue
            
            if self.__urlencoded == 2:
                self.__urlencoded = 1

            if self.__htmlencoded == 1 and self.__buff[self.__i] == '&':
                self.__ustate = self.__state
                self.__state = ScriptDecoder.STATE_HTMLENCODE
                self.__hd = 0
                self.__i += 1
                continue

            if self.__htmlencoded == 2:
                self.__htmlencoded = 1

            if self.__state_functions.has_key(self.__state):
                out += self.__state_functions[self.__state]()
            else:
                print "Internal Error: Invalid state:", self.__state
        return out

    
    def resetStateMachine(self):
        self.__i = 0
        self.__buff = ""
        self.__state = ScriptDecoder.STATE_INIT_COPY
        self.__ustate = 0
        self.__nextstate = 0
        self.__c = 0
        self.__c1 = 0
        self.__lenbuff = ['0' for i in xrange(0, 7)]
        self.__csbuff = ['0' for i in xrange(0, 7)]
        self.__htmldec = ['0' for i in xrange(0, 8)]
        self.__marker = "#@~^"
        self.__k = 0
        self.__m = 0 
        self.__ml = 0
        self.__hd = 0
        self.__utf8 = 0
        self.__csum = 0
        self.__len = 0


    def __unescape(self, c):
        if (ord(c) > 127):
            return c
        escapes = "#&!*$"
        escaped = "\r\n<>@"
        for i in xrange(0, len(escapes)):
            if escapes[i] == c:
                return escaped[i]
        return '?'


    def __decodeMnemonic(self, mnemonic):
        if EntityMap.has_key(mnemonic):
            return chr(EntityMap[mnemonic])
        else:
            print "Warning: did not recognize HTML entity", mnemonic
            return '?'

    def __decodeBase64(self, buff):
        val = 0
	val += self.__digits[ord(buff[0])] << 2
	val += self.__digits[ord(buff[1])] >> 4
	val += (self.__digits[ord(buff[1])] & 0xf) << 12
	val += (self.__digits[ord(buff[2])] >> 2) << 8 
	val += (self.__digits[ord(buff[2])] & 0x3) << 22
	val += self.__digits[ord(buff[3])] << 16
	val += (self.__digits[ord(buff[4])] << 2) << 24
	val += (self.__digits[ord(buff[5])] >> 4) << 24
        return val


    def __isLeabByte(self, cp, ucByte):
        if cp == 932:
            if ucByte > 0x80 and ucByte < 0xa0:
                return 1
            if ucByte > 0xdf and ucByte < 0xfd:
                return 1
            else: 
                return 0
        if cp == 936:
            if ucByte > 0xa0 and ucByte < 0xff:
                return 1
            else:
                return 0
        if cp == 950:
            if ucByte > 0x80 and ucByte < 0xff:
                return 1
            else:
                return 0
        if cp == 1361:
            if ucByte > 0x83 and ucByte < 0xd4:
                return 1
            if ucByte > 0xd8 and ucByte < 0xdf:
                return 1
            if ucByte > 0xdf and ucByte < 0xfa:
                return 1
            else:
                return 0
        return 0
        

    def __makeTrans(self):
        for i in xrange(0, 32):
            for j in xrange(0, 3):
                self.__transformed[j].append(i)
        for i in xrange(31, 128):
            for j in xrange(0, 3):
                if i == 31:
                    self.__transformed[j][RawData[(i-31)*3 + j]] = 9
                else:
                    self.__transformed[j][RawData[(i-31)*3 + j]] = i
    

    def __makeDigits(self):
        for i in xrange(0, 26):
            self.__digits[ord('A')+i] = i
            self.__digits[ord('a')+i] = i+26
        for i in xrange(0, 10):
            self.__digits[ord('0')+i] = i+52
        self.__digits[0x2b] = 62
        self.__digits[0x2f] = 63

            

    # Internal functions dedicated to state machine

    def __stateInitCopy(self):
        self.__ml = len(self.__marker)
        self.__m = 0
        self.__state = ScriptDecoder.STATE_COPY_INPUT
        return ""
        
    
    def __stateWaitForClose(self):
        if self.__buff[self.__i] == '>':
            self.__state = ScriptDecoder.STATE_WAIT_FOR_OPEN
        out = self.__buff[self.__i]
        self.__i += 1
        return out


    def __stateWaitForOpen(self):
        if self.__buff[self.__i] == '<':
            self.__state = ScriptDecoder.STATE_INIT_COPY
        out = self.__buff[self.__i]
        self.__i += 1
        return out


    def __stateCopyInput(self):
        out = ""
        if self.__buff[self.__i] == self.__marker[self.__m]:
            self.__i += 1
            self.__m += 1
        else:
            if self.__m:
                self.__k = 0
                self.__state = ScriptDecoder.STATE_FLUSHING
            else:
                out = self.__buff[self.__i]
                self.__i += 1
        if self.__m == self.__ml:
            self.__state = ScriptDecoder.STATE_INIT_READLEN
        return out


    def __stateFlushing(self):
        self.__k += 1
        out = self.__marker[self.__k]
        self.__m -= 1
        if self.__m == 0:
            self.__state = ScriptDecoder.STATE_COPY_INPUT
        return out
        

    def __stateSkipMl(self):
        self.__i += 1
        self.__ml -= 1
        if not self.__ml:
            self.__state = self.__nextstate
        return ""


    def __stateInitReadLen(self):
        self.__ml = 6
        self.__state = ScriptDecoder.STATE_READLEN
        return ""


    def __stateReadLen(self):
        self.__lenbuff[6-self.__ml] = self.__buff[self.__i]
        self.__i += 1
        self.__ml -= 1
        if not self.__ml:
            self.__len = self.__decodeBase64(self.__lenbuff)
            if self.__verbose:
                print "Msg: Found encoded block containing", self.__len, "characters."
            self.__m = 0
            self.__ml = 2
            self.__state = ScriptDecoder.STATE_SKIP_ML
            self.__nextstate = ScriptDecoder.STATE_DECODE
        return ""


    def __stateDecode(self):
        out = ""
        if not self.__len:
            self.__ml = 6
            self.__state = ScriptDecoder.STATE_CHECKSUM
            return ""
        if self.__buff[self.__i] == '@':
            self.__state = ScriptDecoder.STATE_UNESCAPE
        else:
            if ord(self.__buff[self.__i]) & 0x80 == 0:
                out = chr(self.__transformed[PickEncodings[self.__m%64]][ord(self.__buff[self.__i])])
                self.__csum += ord(out)
                self.__m += 1
            else:
                if not self.__cp and ord(self.__buff[self.__i]) & 0xc0 == 0x80:
                    self.__len += 1
                    self.__utf8 = 1
                out = self.__buff[self.__i]
                if self.__cp and self.__isLeadByte(self.__cp, ord(self.__buff[i])):
                    self.__state = ScriptDecoder.STATE_DBCS
        self.__i += 1
        self.__len -= 1
        return out


    def __stateDbcs(self):
        out = self.__buff[self.__i]
        self.__i += 1
        self.__state = ScriptDecoder.STATE_DECODE
        return out

    
    def __stateUnescape(self):
        out = self.__unescape(self.__buff[self.__i])
        self.__i += 1
        self.__csum += ord(out)
        self.__len -= 1
        self.__m += 1
        self.__state = ScriptDecoder.STATE_DECODE
        return out

    
    def __stateChecksum(self):
        self.__csbuff[6-self.__ml] = self.__buff[self.__i]
        self.__i += 1
        self.__ml -= 1
        if not self.__ml:
            self.__csum -= self.__decodeBase64(self.__csbuff)
            if self.__csum:
                print "Error: Incorrect checksum!", self.__csum
                if self.__cp:
                    print "Tip: Maybe try another codepage."
                else:
                    if self.__utf8 > 0:
                        print "Tip: The file seems to contain special characters, try the -cp option."
                    else:
                        print "Tip: the file may be corrupted."
                self.__csum = 0
            else:
                if self.__verbose:
                    print "Msg: Checksum OK"
            self.__m = 0
            self.__ml = 6
            self.__state = ScriptDecoder.STATE_SKIP_ML
            if self.__smart:
                self.__nextstate = ScriptDecoder.STATE_WAIT_FOR_CLOSE
            else:
                self.__nextstate = ScriptDecoder.STATE_INIT_COPY
        return ""

    
    def __stateUrlEncode1(self):
        self.__c1 = ord(self.__buff[self.__i]) - 0x30
        self.__i += 1
        if self.__c1 > 0x9:
            self.__c1 -= 0x07
        if self.__c1 > 0x10:
            self.__c1 -= 0x20
        self.__state = ScriptDecoder.STATE_URLENCODE_2
        return ""


    def __stateUrlEncode2(self):
        c2 = ord(self.__buff[self.__i]) - 0x30
        if c2 > 0x9:
            c2 -= 0x07
        if c2 > 0x10:
            c2 -= 0x20
        self.__buff = self.__self.__buff[:self.__i] + chr(c2 + c1<<4) + self.__self.__buff[self.__i+1:]
        self.__urlencoded = 2
        self.__state = self.__ustate
        return ""

    
    def __stateHtmlEncode(self):
        self.__c1 = ord(self.__self.__buff[self.__i])
        if chr(self.__c1) != ';':
            self.__i += 1
            self.__hd += 1
            self.__htmldec[self.__hd] = chr(self.__c1)
            if self.__hd > 7:
                self.__htmldec[7] = 0
                raise "Error: HTML decode encountered a too long mnemonic" + self.__htmldec
        else:
            self.__htmldec[self.__hd] = 0
            self.__buff = self.__self.__buff[:self.__i] + self.__decodeMnemonic(self.__htmldec) + self.__self.__buff[self.__i+1:]
            self.__htmlencoded = 2
            self.__state = self.__ustate
        return out



if __name__ == "__main__":
    sd = ScriptDecoder()
    print sd.decodeBuffer("#@~^FQAAAA==@#@&CGb@#@&zz O@*@#@&WwIAAA==^#~@")
    sd.resetStateMachine()
    print sd.decodeBuffer("#@~^lgAAAA==@#@&b)zbzbbzbz)bzb)bzb))zbbz)bzbbz))bzbzb)b))zb)bz)bzb))zbb))zb)bz)zb)zbzbbzbz)bzb)bzb))zbbz)bzbbz))bzbzb)b))zb)bz)bzb))zbb))zb)bz)zb)zb@#@&zJO@*@#@&vyIAAA==^#~@")
    sd.resetStateMachine()
    print sd.decodeBuffer('#@~^QwAAAA==@#@&P~,l^+DDPvEY4kdP1W[n,/tK;V9P4\n~V+aY,/nm.nD"Z"eE#p@#@&&JOO@*@#@&qhAAAA==^#~@')
