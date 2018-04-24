#!/usr/bin/env python2

import json
import argparse


def get_args():
    parser = argparse.ArgumentParser(description="TEDiff is used to compute differences in TED-reports")
    parser.add_argument(dest="first")
    parser.add_argument(dest="second")

    return parser.parse_args()


def diff_elf_noExec(a, b):
    score_a = a["Score"]
    score_b = b["Score"]
    stack_a = a["Stack_executable"]
    stack_b = b["Stack_executable"]
    wx_a = a["W^X enforced"]
    wx_b = b["W^X enforced"]
    nx_a = a["nx_flag"]
    nx_b = b["nx_flag"]
    if score_a == score_b and stack_a == stack_b and wx_a == wx_b and nx_a == nx_b:
        return False, None
    else:
        diff = {}
        if score_a != score_b:
            diff['Score']= {"Score before": score_a, "Score after": score_b}
        if stack_a != stack_b:
            diff['Stack Executable'] = {'Stack executable before': stack_a, "Stack executable after": stack_b}
        if wx_a != wx_b:
            diff['W^X enforced'] = {'W^X before': wx_a, 'W^X': wx_b}
        if nx_a != nx_b:
            diff['nx_flag'] = {'Nx flag before': nx_a, 'Nx flag after': nx_b}
        return True, diff


def diff_elf_ssp(a, b):
    score_a = a['Score']
    score_b = b['Score']
    canaries_a = a['canaries']
    canaries_b = b['canaries']
    ssp_a = a['stack_chk_fail']
    ssp_b = b['stack_chk_fail']

    if score_a == score_b and canaries_a == canaries_b and ssp_a == ssp_b:
        return False, None
    else:
        diff = {}
        if score_b != score_a:
            diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        if canaries_a != canaries_b:
            diff['canaries'] = {'Canaries before': canaries_a, 'Canaries after': canaries_b}
        if ssp_a != ssp_b:
            diff['stack_chk_fail'] = {'Stack smashing protector before' : ssp_a, 'Stack smashing protector after': ssp_b}
        return True, diff


def diff_elf_stripped(a, b):
    score_a = a['Score']
    score_b = b['Score']
    stripped_a = a['Binary stripped']
    stripped_b = b['Binary stripped']
    if stripped_a == stripped_b:
        return False, None
    else:
        diff = {}
        diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        diff['Binary stripped'] = {'Stripped before': stripped_a, 'Stripped after': stripped_b}
        return True, diff


def diff_elf_hash(a, b):
    if a == b:
        return False,None
    else:
        diff = {'Hash before': a, 'Hash after': b}
        return True, diff


def diff_elf_score(a, b):
    if a == b:
        return False,None
    else:
        diff = {'ELF score before': a, 'ELF score after': b}
        return True, diff


def diff_elf_report(a, b):
    score_changed,score_diff = diff_elf_score(a['ELF score'], b['ELF score'])
    noexec_changed,noexec_diff = diff_elf_noExec(a['NoExec'], b['NoExec'])
    ssp_changed,ssp_diff = diff_elf_ssp(a['Stack_Smashing_Protector'], b['Stack_Smashing_Protector'])
    stripped_changed,stripped_diff = diff_elf_stripped(a['Stripped'], b['Stripped'])
    hash_changed,hash_diff = diff_elf_hash(a['sha256'], b['sha256'])
    if not score_changed and not noexec_changed and not ssp_changed and not stripped_changed and not hash_changed:
        return False,None
    else:
        diff_report = {}
        if score_changed:
            diff_report['Score'] = score_diff
        if noexec_changed:
            diff_report['NoExec'] = noexec_diff
        if ssp_changed:
            diff_report['Stack_Smashing_Protector'] = ssp_diff
        if stripped_changed:
            diff_report['Stripped'] = stripped_diff
        if hash_changed:
            diff_report['Sha256'] = hash_diff
        return True, diff_report


def elf_diff(a, b):
    binaries_a = a.keys()
    binaries_b = b.keys()
    binaries_removed = {'Description' : "The binaries in this list are present in the first scan but not in the second"}
    binaries_removed['Removed'] = []
    binaries_added = {'Description' : "The binaries in this list are present in the second scan but not in the first"}
    binaries_added['Added'] = []
    for bin in binaries_a:
        if bin not in binaries_b:
            new_bin = { 'Path': bin, 'Scan': a[bin]}
            binaries_removed['Removed'].append(new_bin)
        else:
            if bin != "Description":
                elf_changed, elf_delta = diff_elf_report(a[bin], b[bin])
                if elf_changed:
                    print "The scan result for "+bin+" changed:"
                    print json.dumps(elf_delta, indent=4,sort_keys=True)
    for bin in binaries_b:
        if bin not in binaries_a:
            new_bin = {'Path': bin, 'Scan': b[bin]}
            binaries_added['Added'].append(new_bin)
    print "The following binaries have been removed from the system:"
    print json.dumps(binaries_removed, indent=4, sort_keys=True)
    print "The following binaries have been added to the system:"
    print json.dumps(binaries_added, indent=4, sort_keys=True)


def diff_system_score(a, b):
    if a == b:
        return False,None
    else:
        diff = {'System score before': a, 'System score after': b}
        return True, diff


def diff_system_aslr(a, b):
    score_a = a['Score']
    score_b = b['Score']
    hard_a = a['ASLR_hard_value']
    hard_b = b['ASLR_hard_value']
    soft_a = a['ASLR_soft_value']
    soft_b = b['ASLR_soft_value']
    if score_a == score_b and hard_a == hard_b and soft_a == soft_b:
        return False, None
    else:
        diff = {}
        if score_a != score_b:
            diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        if hard_a != hard_b:
            diff['ASLR_hard_value'] = {'hard value before': hard_a, 'hard value after': hard_b,
                                       'hard status before': a['ASLR_hard_check'],
                                       'hard status after' : b['ASLR_hard_check']}
        if soft_a != soft_b:
            diff['ASLR_soft_value'] = {'soft value before': hard_a, 'soft value after': hard_b,
                                       'soft status before': a['ASLR_soft_check'],
                                       'soft status after': b['ASLR_soft_check']}
        return True, diff


def diff_system_nx(a, b):
    score_a = a['Score']
    score_b = b['Score']
    nx_a = a['nx_supported']
    nx_b = b['nx_supported']
    if nx_a == nx_b:
        return False,None
    else:
        diff = {}
        diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        diff['Nx supported'] = {'Nx supported before': nx_a, 'Nx supported after': nx_b}
        return True, diff


def diff_system_spectre(a, b):
    score_a = a['Score']
    score_b = b['Score']
    v1vuln_a= a['Variant 1']['vulnerable']
    v1vuln_b =b['Variant 1']['vulnerable']
    v2vuln_a = a['Variant 2']['vulnerable']
    v2vuln_b = b['Variant 2']['vulnerable']
    v3vuln_a = a['Variant 3']['vulnerable']
    v3vuln_b = b['Variant 3']['vulnerable']
    if score_a == score_b and v1vuln_a == v1vuln_b and v2vuln_a == v2vuln_b and v3vuln_a == v3vuln_b:
        return False, None
    else:
        diff = {}
        if score_a != score_b:
            diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        if v1vuln_b != v1vuln_a:
            diff['Variant 1'] = {'Vulnerable variant 1 before': v1vuln_a, 'Vulnerable variant 1 after': v1vuln_b}
        if v2vuln_b != v2vuln_a:
            diff['Variant 2'] = {'Vulnerable variant 2 before': v2vuln_a, 'Vulnerable variant 2 after': v2vuln_b}
        if v3vuln_b != v3vuln_a:
            diff['Variant 3'] = {'Vulnerable variant 3 before': v3vuln_a, 'Vulnerable variant 3 after': v3vuln_b}
        return True, diff


def diff_kpop_list_exploit(a, b):
    for exploit in a:
        if exploit not in b:
            return True
    for exploit in b:
        if exploit not in a:
            return True


def diff_system_kernelpop(a, b):
    #Trivial check
    score_a = a['Score']
    score_b = b['Score']
    confirmed_a = a['confirmed']
    confirmed_b = b['confirmed']
    potential_a = a['potential']
    potential_b = b['potential']
    if score_a == score_a and not diff_kpop_list_exploit(confirmed_a,confirmed_b) and not diff_kpop_list_exploit(potential_a, potential_b):
        return False, None
    else:
        diff= {}
        if score_a != score_b:
            diff['Score'] = {'Score before': score_a, 'Score after': score_b}
        if diff_kpop_list_exploit(confirmed_a,confirmed_b):
            diff['Confirmed exploits'] = {'Confirmed exploit before': confirmed_a, 'Confirmed exploit after': confirmed_b}
        if diff_kpop_list_exploit(potential_a, potential_b):
            diff['Potential exploits'] = {'Potential exploit before': potential_a, 'Potential exploit after': potential_b}
        return True, diff


def diff_system_report(a, b):
    score_before = a["System score"]
    score_after = b["System score"]
    score_changed,score_diff = diff_system_score(score_before,score_after)
    aslr_changed,aslr_diff = diff_system_aslr(a['ASLR'], b['ASLR'])
    nx_changed,nx_diff = diff_system_nx(a['Nx_support'], b['Nx_support'])
    spectre_changed,spectre_diff = diff_system_spectre(a['Spectre_meltdown'], b['Spectre_meltdown'])
    kernelpop_changed,kernelpop_diff = diff_system_kernelpop(a['Kernelpop'], b['Kernelpop'])
    if not score_changed and not aslr_changed and not nx_changed and not spectre_changed and not kernelpop_changed:
        return False, None
    else:
        difference_system= {}
        if score_changed:
            difference_system['Score'] = score_diff
        if aslr_changed:
            difference_system['ASLR'] = aslr_diff
        if nx_changed:
            difference_system['Nx support'] = nx_diff
        if spectre_changed:
            difference_system['Spectre and meltdown'] = spectre_diff
        if kernelpop_changed:
            difference_system['Kernelpop'] = kernelpop_diff
        return True, difference_system


def diff_time_scan(a, b):
    if a == b:
        return False, None
    else:
        diff = {'Date before': a, 'Date after': b}
        return True, diff


def diff():
    args = get_args()
    before = args.first
    after = args.second
    before_json = json.load(open(before))
    after_json = json.load(open(after))
    type_a = before_json['type']
    type_b = after_json['type']
    if type_a != type_b:
        raise RuntimeError("Cannot compare scans of different types")
    date_changed,date_diff = diff_time_scan(before_json['time'], after_json['time'])
    if date_changed:
        print json.dumps(date_diff, indent=4)
    elfs_a = before_json['ELFs']
    elfs_b = after_json['ELFs']
    elf_diff(elfs_a,elfs_b)
    if type_a == "full":
        system_a = before_json['System checks']
        system_b = after_json['System checks']
        system_changed,delta_system = diff_system_report(system_a, system_b)
        if system_changed:
            print json.dumps(delta_system, indent=4, sort_keys=True)

diff()