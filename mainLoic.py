import sys
import csv
import re
import ntpath

print sys.argv

# variables that can be used in expressions
# Everywhere:
#   process: process object
# Session checks:
#   p_sess : pointer to the session object
#   session : the session object
#   sessid : the session id of the session
# Priority checks
#   prio : the process priority
# Command line checks

list_name_regexs = [
    # system
    ['system', [
                    re.compile(r'^system$')
                ]
    ],
    
    # smss.exe
    ['smss', [
                    re.compile(r's..s\.exe')
                ]
    ],
    
    # csrss.exe
    ['csrss', [
                    re.compile(r'c...s\.exe')
                ]
    ],
    
    # winlogon.exe
    ['winlogon', [
                        re.compile(r'w.nl.g.n\.exe')
                    ]
    ],
    
    # wininit.exe
    ['wininit', [
                    re.compile(r'w.n.n.t\.exe')
                ]
    ],
    
    # services.exe
    ['services', [
                    re.compile(r's.rv.ce.\.exe')
                ]
    ],
    
    # lsass.exe
    ['lsass', [
                re.compile(r'lsass\.exe'),
                re.compile(r'ls.ass\.exe')
              ]
    ],
    
    # spoolsv.exe
    ['spoolsv', [
                    re.compile(r'spool..\.exe')
                ]
    ],
    
    # conhost.exe
    ['conhost', [
                    re.compile(r'con....\.exe')
                ]
    ],
    
    # explorer.exe
    ['explorer', [
                    re.compile(r'explorer\.exe')
                ]
    ],
    
    # taskhost.exe
    ['taskhost', [
                    re.compile(r't.skh.st\.exe')
                ]
    ],
    
    # wmiprvse.exe
    ['wmiprvse', [
                    re.compile(r'wmiprvse\.exe')
                ]
    ],
    
    # svchost.exe
    ['svchost', [
                    re.compile(r's..h.st\.exe|s.host\.exe', re.I),
                    re.compile(r'.*s..h.st.*\.exe', re.I),
                    re.compile(r's..h.s\.exe', re.I)
                ]
    ],
    
    # cmd.exe
    ['cmd', [
                re.compile(r'cmd\.exe')
            ]
    ],
    
    # dwm.exe
    ['dwm', [
                re.compile(r'dwm\.exe'),
            ]
    ],
    
    # notepad.exe
    ['notepad', [
                    re.compile(r'n.t.p.d\.exe')
                ]
    ],
    
    # lsm.exe
    ['lsm', [
                re.compile(r"lsm\.exe")
            ]
    ],
    
    # ccsvchst.exe - Symantec process
    ['ccsvchst', [
                    re.compile(r'..svchst\.exe')
                ]
    ],
    
    # rundll32.exe
    ['rundll32', [
                    re.compile(r'run...32\.exe')
                ]
    ],
    
    # iexplore.exe
    ['iexplore', [
                    re.compile(r'iexplore\.exe')
                ]
    ],
]

list_bad_paths = [
    # Temp folders
    re.compile(r'\\temp\\',re.I),
    re.compile(r'\\temporary internet files\\', re.I),
    re.compile(r'\\tmp\\'),
    
    # System volume information
    re.compile(r'\\system volume information\\', re.I),
    
    # Recycle bin
    re.compile(r'\\recycler\\', re.I),
    re.compile(r'\\recycle\.bin\\', re.I)
]

well_known_sids = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2': 'Local Authority',
  'S-1-2-0': 'Local (Users with the ability to log in locally)',
  'S-1-2-1': 'Console Logon (Users who are logged onto the physical console)',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-3-4': 'Owner Rights',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-14': 'Remote Interactive Logon',
  'S-1-5-15': 'This Organization',
  'S-1-5-17': 'This Organization (Used by the default IIS user)',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
  'S-1-5-32-568': 'BUILTIN\IIS IUSRS',
  'S-1-5-32-569': 'Cryptographic Operators',
  'S-1-5-32-573': 'BUILTIN\Event Log Readers',
  'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
  'S-1-5-33': 'Write Restricted',
  'S-1-5-64-10': 'NTLM Authentication',
  'S-1-5-64-14': 'SChannel Authentication',
  'S-1-5-64-21': 'Digest Authentication',
  'S-1-5-80': 'NT Service',
  'S-1-5-86-1544737700-199408000-2549878335-3519669259-381336952': 'WMI (Local Service)',
  'S-1-5-86-615999462-62705297-2911207457-59056572-3668589837': 'WMI (Network Service)',
  'S-1-5-1000': 'Other Organization',
  'S-1-16-0': 'Untrusted Mandatory Level',
  'S-1-16-4096': 'Low Mandatory Level',
  'S-1-16-8192': 'Medium Mandatory Level',
  'S-1-16-8448': 'Medium Plus Mandatory Level',
  'S-1-16-12288': 'High Mandatory Level',
  'S-1-16-16384': 'System Mandatory Level',
  'S-1-16-20480': 'Protected Process Mandatory Level',
  'S-1-16-28672': 'Secure Process Mandatory Level',
}

well_known_sid_re = [
  (re.compile(r'S-1-5-[0-9-]+-500'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502'), 'KRBTGT'),
]

####################################################################
# PARENT CHECKS FUNCTIONS
####################################################################
def system_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) == 0:
        return True
    else:
        return False

def smss_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) == 4:
        return True
    else:
        p = list_all[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "smss.exe":
            return True
        else:
            return False

def wininit_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) in list_all:
        p = list_all[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "smss.exe":
            return True
        else:
            return False
    else:
        return True

def lsass_parent_chk(process):
    if int(process.obj_native_vm.profile.metadata['major']) > 5:
        # in Vista and above wininit starts lsass.exe
        wininitpid = -1
        for p in list_sysprocs:
            if str(list_sysprocs[p].ImageFileName).lower() == "wininit.exe":
                wininitpid = int(list_sysprocs[p].UniqueProcessId)
        
        if wininitpid == -1:
            return False
        
        if int(process.InheritedFromUniqueProcessId) == wininitpid:
            return True
        else:
            return False
    elif int(process.obj_native_vm.profile.metadata['major']) == 5:
        # in windows XP and server 2003 winlogon is responsible
        winlogonpid = []
        for p in list_sysprocs:
            if str(list_sysprocs[p].ImageFileName).lower() == "winlogon.exe":
                winlogonpid.append(int(list_sysprocs[p].UniqueProcessId))
        
        if len(winlogonpid) == 0:
            return False
        
        if int(process.InheritedFromUniqueProcessId) in winlogonpid:
            return True
        else:
            return False

def services_parent_chk(process):
    if int(process.obj_native_vm.profile.metadata['major']) > 5:
        # Beginning wiht Vista wininit.exe will start services.exe
        wininitpid = -1
        for p in list_sysprocs:
            if str(list_sysprocs[p].ImageFileName).lower() == "wininit.exe":
                wininitpid = int(list_sysprocs[p].UniqueProcessId)
        
        if wininitpid == -1:
            return False
        
        if int(process.InheritedFromUniqueProcessId) == wininitpid:
            return True
        else:
            return False
    elif int(process.obj_native_vm.profile.metadata['major']) == 5:
        # in windows XP and server 2003 it's winlogon.exe
        winlogonpid = []
        for p in list_sysprocs:
            if str(list_sysprocs[p].ImageFileName).lower() == "winlogon.exe":
                winlogonpid.append(int(list_sysprocs[p].UniqueProcessId))
                
        if len(winlogonpid) == 0:
            return False
        
        if int(process.InheritedFromUniqueProcessId) in winlogonpid:
            return True
        else:
            return False

def conhost_parent_chk(process):
    ok = False
    for pid in list_csrss:
        if pid == int(process.InheritedFromUniqueProcessId):
            ok = True
    return ok

def svchost_parent_chk(process):
    servicespid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "services.exe":
            servicespid = int(list_sysprocs[p].UniqueProcessId)
    
    if servicespid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == servicespid:
        return True
    else:
        return False

def taskhost_parent_chk(process):
    servicespid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "services.exe":
            servicespid = int(list_sysprocs[p].UniqueProcessId)
    
    if servicespid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == servicespid:
        return True
    else:
        return False

def lsm_parent_chk(process):
    wininitpid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "wininit.exe":
            wininitpid = int(list_sysprocs[p].UniqueProcessId)
    
    if wininitpid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == wininitpid:
        return True
    else:
        return False

def wmiprvse_parent_chk(process):
    ok = False
    for pid in list_svchost:
        if pid == int(process.InheritedFromUniqueProcessId):
            ok = True
    return ok

def spoolsv_parent_chk(process):
    servicespid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "services.exe":
            servicespid = int(list_sysprocs[p].UniqueProcessId)
    
    if servicespid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == servicespid:
        return True
    else:
        return False

def cmd_parent_chk(process):
    explorerpid = []
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "explorer.exe":
            explorerpid.append(int(list_sysprocs[p].UniqueProcessId))
    
    if len(explorerpid) == 0:
        return False
    
    if int(process.InheritedFromUniqueProcessId) in explorerpid:
        return True
    else:
        return False

def dwm_parent_chk(process):
    ok = False
    for pid in list_svchost:
        if pid == int(process.InheritedFromUniqueProcessId):
            ok = True
    return ok

def notepad_parent_chk(process):
    explorerpid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "explorer.exe":
            explorerpid = int(list_sysprocs[p].UniqueProcessId)
    
    if explorerpid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == explorerpid:
        return True
    else:
        return False

def explorer_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) in list_all:
        p = list_all[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "userinit.exe":
            return True
        else:
            return False
    else:
        return True

def csrss_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) in list_all:
        p = list_all[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "smss.exe":
            return True
        else:
            return False
    else:
        return True

def winlogon_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) in list_all:
        p = list_all[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "smss.exe":
            return True
        else:
            return False
    else:
        return True

def userinit_parent_chk(process):
    if int(process.InheritedFromUniqueProcessId) in list_all:
        p = list_sysprocs[int(process.InheritedFromUniqueProcessId)]
        if str(p.ImageFileName).lower() == "winlogon.exe":
            return True
        else:
            return False
    else:
        return True

def ccsvchst_parent_chk(process):
    session = obj.Object('_MM_SESSION_SPACE', process.Session.v(), process.obj_native_vm)
    
    if session == None:
        return False
    
    sessid = int(session.SessionId)
    
    ppid = int(process.InheritedFromUniqueProcessId)
    
    if sessid == 0:
        if ppid in list_sysprocs:
            if str(list_sysprocs[ppid].ImageFileName).lower().strip() == "services.exe":
                return True
            else:
                return False
        else:
            return False
    elif sessid > 0:
        if ppid in list_all:
            if str(list_all[ppid].ImageFileName).lower().strip() == "ccsvchst.exe":
                return True
            else:
                return False
        else:
            return False

def rundll32_parent_chk(process):
    # Usually it has a parent process
    if int(process.InheritedFromUniqueProcessId) in list_all:
        return True
    else:
        return False

def iexplore_parent_chk(process):
    explorerpid = -1
    for p in list_sysprocs:
        if str(list_sysprocs[p].ImageFileName).lower() == "explorer.exe":
            explorerpid = int(list_sysprocs[p].UniqueProcessId)
    
    if explorerpid == -1:
        return False
    
    if int(process.InheritedFromUniqueProcessId) == explorerpid:
        return True
    elif (list_all[int(process.InheritedFromUniqueProcessId)].ImageFileName).lower() == "iexplore.exe":
        return True
    else:
        return False

####################################################################
# USER CHECKS FUNCTIONS
####################################################################

def explorer_user_chk(process, token):
    # explorer runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        return True
    else:
        return False

def taskhost_user_chk(process, token):
    # taskhost runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        return True
    else:
        return False

def conhost_user_chk(process, token):
    session = obj.Object('_MM_SESSION_SPACE',
                         process.Session.v(),
                         process.obj_native_vm)
    
    if session == None:
        return False
    
    sessid = int(session.SessionId)
    sid = token.get_sids().next()
    
    if sessid == 0:
        if sid == "S-1-5-18":
            return True
        else:
            return False
    elif sessid > 0:
        if sid not in well_known_sids:
            return True
        else:
            return False

def cmd_user_chk(process, token):
    # cmd usually runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        ok = True
        for regexp in well_known_sid_re:
            if regexp[0].match(sid):
                ok = False
        return ok
    else:
        return False

def dwm_user_chk(process, token):
    # dwm usually runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        ok = True
        for regexp in well_known_sid_re:
            if regexp[0].match(sid):
                ok = False
        return ok
    else:
        return False

def notepad_user_chk(process, token):
    # notepad usually runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        ok = True
        for regexp in well_known_sid_re:
            if regexp[0].match(sid):
                ok = False
        return ok
    else:
        return False

def userinit_user_chk(process, token):
    # userinit usually runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        ok = True
        for regexp in well_known_sid_re:
            if regexp[0].match(sid):
                ok = False
        return ok
    else:
        return False

def ccsvchst_user_chk(process, token):
    session = obj.Object('_MM_SESSION_SPACE',
                         process.Session.v(),
                         process.obj_native_vm)
    
    if session == None:
        return False
    
    sessid = int(session.SessionId)
    
    sid = token.get_sids().next()
    
    if sessid == 0:
        if sid == 'S-1-5-18':
            return True
        else:
            return False
    elif sessid > 0:
        if sid not in well_known_sids:
            return True
        else:
            return False

def rundll32_user_chk(process, token):
    session = obj.Object('_MM_SESSION_SPACE',
                         process.Session.v(),
                         process.obj_native_vm)
    
    if session == None:
        return False
    
    sessid = int(session.SessionId)
    
    sid = token.get_sids().next()
    
    if sessid == 0:
        return False
    elif sessid > 0:
        if sid not in well_known_sids:
            return True
        else:
            return False

def iexplore_user_chk(process, token):
    # iexplore usually runs on behalf of the logged in user
    sid = token.get_sids().next()
    
    if sid not in well_known_sids:
        ok = True
        for regexp in well_known_sid_re:
            if regexp[0].match(sid):
                ok = False
        return ok
    else:
        return False


####################################################################
# DEFAULT DEFINITIONS
####################################################################

defaults = {

'system' : {
    'name' : ["system"],
    'path' : None,
    'priority' : 'prio == 8',
    'cmdline'  : None,
    'session'  : 'p_sess == 0',
    'user' : ["S-1-5-18"],
    'parent' : system_parent_chk,
    'time': None
    
},

'smss' : {
    'name' : ["smss.exe"],
    'path' : ["\systemroot\system32\smss.exe"],
    'priority' : 'prio == 11',
    'cmdline'  : ["\systemroot\system32\smss.exe"],
    'session'  : 'p_sess == 0',
    'user' : ["S-1-5-18"],
    'parent' : smss_parent_chk, # should be system
    'time': None
},

'wininit' : {
    'name' : ["wininit.exe"],
    'path' : ["c:\windows\system32\wininit.exe"],
    'priority' : 'prio == 13',
    'cmdline'  : ["wininit.exe"],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18"],
    'parent' : wininit_parent_chk,
    'time': 45
},

'lsass' : {
    'name' : ["lsass.exe"],
    'path' : ["c:\windows\system32\lsass.exe"],
    'priority' : 'prio == 9',
    'cmdline'  : ["c:\windows\system32\lsass.exe"],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18"],
    'parent' : lsass_parent_chk,
    'time': 60
},

'userinit' : {
    'name' : ["userinit.exe"],
    'path' : None,
    'priority' : 'prio == 8',
    'cmdline'  : None,
    'session'  : 'sessid > 0',
    'user' : userinit_user_chk,
    'parent' : userinit_parent_chk,
    'time': 60
},

'winlogon' : {
    'name' : ["winlogon.exe"],
    'path' : [
                r"c:\windows\system32\winlogon.exe",
                r"\??\c:\windows\system32\winlogon.exe"
            ],
    'priority' : 'prio == 13',
    'cmdline'  : ["winlogon.exe"],
    'session'  : 'sessid > 0',
    'user' : ["S-1-5-18"],
    'parent' : winlogon_parent_chk,
    'time': None
},

'explorer' : {
    'name' : ["explorer.exe"],
    'path' : [
                "c:\windows\explorer.exe",
                "c:\windows\syswow64\explorer.exe"
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    "c:\windows\explorer.exe",
                    "explorer.exe"
                ],
    'session'  : 'sessid > 0',
    'user' : explorer_user_chk,
    'parent' : explorer_parent_chk,
    'time': None
},

'services' : {
    'name' : ["services.exe"],
    'path' : ["c:\windows\system32\services.exe"],
    'priority' : 'prio == 9',
    'cmdline'  : ["c:\windows\system32\services.exe"],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18"],
    'parent' : services_parent_chk,
    'time': 45
},

'lsm' : {
    'name' : ["lsm.exe"],
    'path' : ["c:\windows\system32\lsm.exe"],
    'priority' : 'prio == 8',
    'cmdline'  : ["c:\windows\system32\lsm.exe"],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18"],
    'parent' : lsm_parent_chk, # should be wininit.exe
    'time': 60
},

'conhost' : {
    'name' : ["conhost.exe"],
    'path' : ["c:\windows\system32\conhost.exe"],
    'priority' : 'prio == 8',
    'cmdline'  : [
            re.compile(r'^\\\?\?\\c:\\windows\\system32\\conhost\.exe ".\d{1,}-\d{1,}-\d{1,}')
        ],
    'session'  : 'sessid >= 0',
    'user' : conhost_user_chk,
    'parent' : conhost_parent_chk,
    'time': None
},

'csrss' : {
    'name' : ["csrss.exe"],
    'path' : [
            "c:\windows\system32\csrss.exe",    # On Win7
            "\??\c:\windows\system32\csrss.exe" # On WinXP
        ],
    'priority' : 'prio == 13',
    'cmdline'  : [
            re.compile(r'^(c:\\windows|%systemroot%)\\system32\\csrss.exe objectdirectory=\\windows sharedsection=\d{2,4},\d{3,6},\d{2,4} windows=on subsystemtype=windows [(serverdll=basesrv,1 |serverdll=winsrv:userserverdllinitialization,3 |serverdll=winsrv:conserverdllinitialization,2 |serverdll=sxssrv=4 )]+profilecontrol=off maxrequestthreads=16')
        ],
    'session'  : 'sessid >= 0',
    'user' : ["S-1-5-18"],
    'parent' : csrss_parent_chk,
    'time': 60
},

'svchost' : {
    'name' : ["svchost.exe"],
    'path' : [
                r"c:\windows\system32\svchost.exe",
                r"c:\windows\syswow64\svchost.exe"
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
            r"c:\windows\system32\svchost.exe -k secsvcs",
            r"c:\windows\system32\svchost.exe -k networkservice",
            r"c:\windows\system32\svchost.exe -k dcomlaunch",
            r"c:\windows\system32\svchost -k dcomlaunch",
            r"c:\windows\system32\svchost.exe -k rpcss",
            r"c:\windows\system32\svchost -k rpcss",
            r"c:\windows\system32\svchost.exe -k netsvcs",
            r"c:\windows\system32\svchost.exe -k localservice",
            r"c:\windows\system32\svchost.exe -k imgsvc",
            r"c:\windows\system32\svchost.exe -ktermsvcs",
            r"c:\windows\system32\svchost.exe -k termsvcs",
            r"c:\windows\system32\svchost.exe -k regsvc",
            r"c:\windows\system32\svchost.exe -k winerr",
            r"c:\windows\system32\svchost.exe -k tapisrv",
            r"c:\windows\system32\svchost.exe -k httpfilter",
            r"c:\windows\system32\svchost.exe -k secvcs",
            r"c:\windows\system32\svchost.exe -k gpsvcgroup",
            r"c:\windows\system32\svchost.exe -k iissvcs",
            r"c:\windows\system32\svchost.exe -k apphost",
            r"c:\windows\system32\svchost.exe -k localsystemnetworkrestricted",
            r"c:\windows\system32\svchost.exe -k wersvcgroup",
            r"c:\windows\system32\svchost.exe -k localserviceandnoimpersonation",
            r"c:\windows\system32\svchost.exe -k localservicenonetwork",
            r"c:\windows\system32\svchost.exe -k localservicenetworkrestricted",
            r"c:\windows\system32\svchost.exe -k networkservicenetworkrestricted",
            r"c:\windows\syswow64\svchost.exe -k iasjet"
        ],
    'session'  : 'sessid >= 0',
    'user' : ["S-1-5-18", "S-1-5-19", "S-1-5-20"],
    'parent' : svchost_parent_chk,
    'time': 60
},

'taskhost' : {
    'name' : ["taskhost.exe"],
    'path' : [r"c:\windows\system32\taskhost.exe"],
    'priority' : 'prio == 8',
    'cmdline'  : [
                '"taskhost.exe"',
                'taskhost.exe user'
                  ],
    'session'  : 'sessid >= 0',
    'user' : taskhost_user_chk,
    'parent' : taskhost_parent_chk,
    'time': None
},

'wmiprvse' : {
    'name' : ["wmiprvse.exe"],
    'path' : [
                "c:\windows\system32\wbem\wmiprvse.exe",
                "c:\windows\syswow64\wbem\wmiprvse.exe"
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
                "c:\windows\syswow64\wbem\wmiprvse.exe -embedding",
                "c:\windows\system32\wbem\wmiprvse.exe"
                ],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18", "S-1-5-20"],
    'parent' : wmiprvse_parent_chk,
    'time': 60
},

'spoolsv' : {
    'name' : ["spoolsv.exe"],
    'path' : ["c:\windows\system32\spoolsv.exe"],
    'priority' : 'prio == 8',
    'cmdline'  : ["c:\windows\system32\spoolsv.exe"],
    'session'  : 'sessid == 0',
    'user' : ["S-1-5-18"],
    'parent' : spoolsv_parent_chk,
    'time': 60
},

'cmd' : {
    'name' : ["cmd.exe"],
    'path' : [
            r"c:\windows\system32\cmd.exe",
            r"c:\windows\syswow64\cmd.exe"],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    r'"c:\windows\system32\cmd.exe"',
                    r'"c:\windows\system32\cmd.exe" ',
                    r'"c:\windows\syswow64\cmd.exe"',
                    r"c:\windows\system32\cmd.exe",
                    r"c:\windows\syswow64\cmd.exe"
                ],
    'session'  : 'sessid > 0',
    'user' : cmd_user_chk,
    'parent' : cmd_parent_chk,
    'time': None
},

'dwm' : {
    'name' : ["dwm.exe"],
    'path' : [r"c:\windows\system32\dwm.exe"],
    'priority' : 'prio == 13',
    'cmdline'  : [
                    r"c:\windows\system32\dwm.exe",
                    r'"c:\windows\system32\dwm.exe"'
                ],
    'session'  : 'sessid > 0',
    'user' : dwm_user_chk,
    'parent' : dwm_parent_chk,
    'time': 60
},

'notepad' : {
    'name' : ["notepad.exe"],
    'path' : [
                r"c:\windows\system32\notepad.exe",
                r"c:\windows\syswow64\notepad.exe"
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    r"c:\windows\system32\notepad.exe",
                    r"c:\windows\syswow64\notepad.exe",
                    r'"c:\windows\system32\notepad.exe"',
                    r'"c:\windows\syswow64\notepad.exe"'
                ],
    'session'  : 'sessid > 0',
    'user' : notepad_user_chk,
    'parent' : notepad_parent_chk,
    'time': None
},

'ccsvchst' : {
    'name' : ["ccsvchst.exe"],
    'path' : [re.compile(r'c:\\program files\\symantec antivirus\\.*\\bin\\ccsvchst.exe')],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    re.compile(r'"c:\\program files\\symantec antivirus\\.*\\bin\\ccsvchst.exe" /s "symantec endpoint protection" /m "c:\\program files\\symantec antivirus\\.*\\bin\\sms.dll" /prefetch:1'),
                    re.compile(r'"c:\\program files\\symantec antivirus\\.*\\bin\\ccsvchst.exe" /u /c /a /s "usersession"')
                ],
    'session'  : 'sessid >= 0',
    'user' : ccsvchst_user_chk,
    'parent' : ccsvchst_parent_chk,
    'time': 60
},

'rundll32' : {
    'name' : ["rundll32.exe"],
    'path' : [
                re.compile(r'c:\\windows\\system32\\rundll32.exe'),
                re.compile(r'c:\\windows\\syswow64\\rundll32.exe')
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    re.compile(r'c:\\windows\\system32\\rundll32.exe')
                ],
    'session'  : 'sessid > 0',
    'user' : rundll32_user_chk,
    'parent' : rundll32_parent_chk,
    'time': None
},

'iexplore' : {
    'name' : ["iexplore.exe"],
    'path' : [
                re.compile(r'c:\\program files\\internet explorer\\iexplore.exe'),
                re.compile(r'c:\\program files (x86)\\internet explorer\\iexplore.exe'),
            ],
    'priority' : 'prio == 8',
    'cmdline'  : [
                    re.compile(r'c:\\program files\\internet explorer\\iexplore.exe'),
                    re.compile(r'c:\\program files (x86)\\internet explorer\\iexplore.exe'),
                    re.compile(r'"c:\\program files\\internet explorer\\iexplore.exe"'),
                    re.compile(r'"c:\\program files (x86)\\internet explorer\\iexplore.exe"'),
                ],
    'session'  : 'sessid > 0',
    'user' : iexplore_user_chk,
    'parent' : iexplore_parent_chk,
    'time': None
},
}
    
# Checks the process name
def check_proc_name(processImageFileName):
   # print "enter fonction check_proc_name"
    ok = False
    for val in defaults:
        for n in defaults[val]['name']:
            #print n
            if n == str(processImageFileName).lower():
               ok = True
    return ok

#fonction qui recherche les typosquating, retourne le nom attendu
def check_proc_name_typo(processImageFileName):
  #  print "enter fonction check_proc_name_typo"
    nomExe=''
    #procname = 
    procname=str(processImageFileName).lower()
 #   print procname
    found = False
    for regexp in list_name_regexs:
        #print regexp
        for r in regexp[1]:
#            print r
            if r.match(procname):
                found = True
                break
        if found: 
            print "found****" 
            print regexp[0]
            nomExe=regexp[0]
            break
    return nomExe




with open(sys.argv[1], 'rb') as csvfile:
    #spamreader = csv.DictReader(csvfile, delimiter=' ', quotechar='|')
    spamreader = csv.DictReader(csvfile)
    for row in spamreader:
        #print(row['_time'], row['process'])
        #On commence par verifier que le nom du process appartient a la liste predefinie
        if row['process'] == '':
           print "*********** pas de nom de process "
           pass
        else:
           print "*********** recherche de "+row['process']
           res=check_proc_name(row['process'])
           if res==True:
                print "exe trouve"
           else:
                print "exe pas trouve, on cherche un typo"
                #on recherche un eventuel typosquating
                res=check_proc_name_typo(row['process'])
                if res!='':
                    print "exe typosquate trouve"
                else:
                    print "exe typo pas trouve"
                   
                 



defaults = {'system' : {'name' : ["system"],'priority' : 'prio == 8',},'smss' : {    'name' : ["smss.exe"],    'priority' : 'prio == 11',}}
