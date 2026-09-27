# SPDX-License-Identifier: AGPL-3.0-only
"""Independent actual Git fixtures for inventory omissions and source escapes."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import reconciliation as policy


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init','-q')
        self.git('config','user.email','fixture@example.invalid')
        self.git('config','user.name','Fixture')
        self.git('remote','add','origin','https://github.com/ArcForges/DesktopPlatform.git')

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.root),*args],text=True).strip()

    def commit(self, files):
        for name,body in files.items():
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding='utf-8')
        self.git('add','.');self.git('commit','-qm','fixture')
        return self.git('rev-parse','HEAD')

    def test_registry_rejects_omission_duplicate_owner_target_and_unsafe_path(self):
        original=[policy.read(n) for n in ['source','current','historical','directories','native']]
        policy.validate(*original)
        for kind in ['owner','project','history','directory','native','duplicate','target','path','producer','candidate','origin']:
            with self.subTest(kind=kind):
                values=copy.deepcopy(original);source,current,history,directories,native=values
                if kind=='owner':current.pop()
                elif kind=='project':current[0]['projects'].pop()
                elif kind=='history':history.pop()
                elif kind=='directory':directories.pop()
                elif kind=='native':native.pop()
                elif kind=='duplicate':directories.append(directories[0])
                elif kind=='target':history[0]['target']='unregistered/path'
                elif kind=='path':directories[0]['path']='../outside'
                elif kind=='producer':history[0]['producer']=''
                elif kind=='candidate':current[0]['candidate']['sourceCommit']='0'*40
                elif kind=='origin':current[0]['origin']='https://example.invalid/source'
                with self.assertRaises(ValueError):policy.validate(*values)

    def test_historical_missing_extra_and_modified_blob(self):
        old=self.commit({'src/A/A.csproj':'<Project />','readme.md':'fixture'})
        files=policy.tree(self.root,old)
        history=[{'path':'src/A/A.csproj','blob':files['src/A/A.csproj'],'observedInDesktopPlatform':'unchanged'}]
        policy.check_history(files,history,files)
        changed=self.commit({'src/A/A.csproj':'<Project><PropertyGroup /></Project>','src/B/B.csproj':'<Project />'})
        with self.assertRaisesRegex(ValueError,'historical project/blob drift'):policy.check_history(policy.tree(self.root,changed),history,files)
        with self.assertRaises(ValueError):policy.check_history({},history,files)
        with self.assertRaisesRegex(ValueError,'observation drift'):policy.check_history(files,history,{})

    def test_submodule_and_symlink_git_modes_are_rejected(self):
        commit=self.commit({'readme.md':'fixture'})
        blob=self.git('hash-object','readme.md')
        for mode,object_id in [('160000',commit),('120000',blob)]:
            with self.subTest(mode=mode):
                self.git('update-index','--add','--cacheinfo',mode,object_id,'linked')
                self.git('commit','-qm','linked fixture')
                with self.assertRaisesRegex(ValueError,'linked source/submodule'):policy.tree(self.root,'HEAD')
                self.git('update-index','--force-remove','linked')

    def test_current_extra_missing_and_changed_project(self):
        self.commit({'src/A/A.csproj':'<Project />'})
        files=policy.tree(self.root,'HEAD')
        row={'repository':'DesktopPlatform','origin':'https://github.com/ArcForges/DesktopPlatform.git','projects':[{'path':'src/A/A.csproj','blob':files['src/A/A.csproj']}]}
        for changed in [{},{**files,'src/B/B.csproj':'0'*40},{'src/A/A.csproj':'0'*40}]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):policy.check_projects(self.root,row,changed,True)

    def test_reviewed_project_update_preserves_snapshot_and_rejects_unreviewed_drift(self):
        row = next(r for r in policy.read('current') if r['repository'] == 'DesktopPlatform')
        original = copy.deepcopy(row)
        updates = policy.read('project-updates')
        reviewed = policy.reviewed_projects(row, updates)
        self.assertEqual(row, original)
        expected = {p['path']:p['blob'] for p in reviewed['projects']}
        for update in updates:
            self.assertEqual(expected[update['path']], update['reviewedBlob'])
        self.assertEqual({a['path'] for a,b in zip(row['projects'],reviewed['projects']) if a != b},
                         {update['path'] for update in updates})
        for field,value in [('path','src/Unknown/Unknown.csproj'),('originalBlob','0'*40),
                            ('reviewedBlob',updates[0]['originalBlob']),('repository','Contracts'),
                            ('producer',''),('authorityCommit','invalid')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.reviewed_projects(row,[dict(updates[0],**{field:value})])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            policy.reviewed_projects(row, updates + updates)
        project = updates[0]['path']
        fixture = dict(row, projects=[{'path':project,'blob':updates[0]['reviewedBlob']}])
        with self.assertRaisesRegex(ValueError,'pinned project blob drift'):
            policy.check_projects(self.root, fixture, {project:'0'*40}, True)

    def test_active_inventory_is_reviewed_and_retired_roots_cannot_return(self):
        row={'repository':'DesktopPlatform','projects':[]}
        original=policy.read('active-projects')
        with patch.object(policy,'read',return_value=original):
            self.assertEqual(policy.active_projects(row)['projects'],original['projects'])
        for mutate in [lambda x:x['projects'].append(x['projects'][0]),
                       lambda x:x['projects'][0].update(path='../outside.csproj'),
                       lambda x:x['projects'][0].update(blob='HEAD'),
                       lambda x:x['projects'][0].update(path='native/arcmedia-ffmpeg-abi/CMakeLists.txt'),
                       lambda x:x.update(authority='unreviewed')]:
            value=copy.deepcopy(original);mutate(value)
            with patch.object(policy,'read',return_value=value),self.assertRaises(ValueError):
                policy.active_projects(row)
        policy.check_retirement({'native/arcimage-abi/CMakeLists.txt':'a'})
        for files in [{}, {'native/arcimage-abi/CMakeLists.txt':'a','native/arcslate-color-abi/CMakeLists.txt':'b'}]:
            with self.assertRaises(ValueError): policy.check_retirement(files)

    def test_present_absent_and_foreign_directory(self):
        self.commit({'src/A/A.csproj':'<Project />'})
        trees={'DesktopPlatform':policy.tree(self.root,'HEAD'),'Contracts':{}}
        rows=[{'owner':'DesktopPlatform','path':'src/A','present':True},{'owner':'Contracts','path':'public/proto','present':False}]
        policy.check_directories(rows,trees)
        for change in [dict(rows[0],present=False),dict(rows[0],owner='Contracts'),dict(rows[1],present=True)]:
            with self.subTest(change=change),self.assertRaises(ValueError):policy.check_directories([change],trees)

    def test_reference_escape_is_rejected_by_owned_checker(self):
        project='src/A/A.csproj'
        self.commit({project:'<Project><PropertyGroup><PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression><LicenceBoundary>AGPL</LicenceBoundary></PropertyGroup><ItemGroup><ProjectReference Include="../../../sibling/B.csproj" /></ItemGroup></Project>',
                     'eng/policy/licence-boundary.json':json.dumps({'schemaVersion':1,'repository':'DesktopPlatform','spdxLicense':'AGPL-3.0-only','licenceBoundary':'AGPL','projects':[{'path':project,'kind':'msbuild'}]})})
        files=policy.tree(self.root,'HEAD')
        row={'repository':'DesktopPlatform','origin':'https://github.com/ArcForges/DesktopPlatform.git','projects':[{'path':project,'blob':files[project]}]}
        for origin in [row['origin'],row['origin'].removesuffix('.git')]:
            self.git('remote','set-url','origin',origin)
            with self.assertRaisesRegex(ValueError,'escapes repository'):policy.check_projects(self.root,row,files,True)
        self.git('remote','set-url','origin','https://github.com/Other/DesktopPlatform.git')
        with self.assertRaisesRegex(ValueError,'origin drift'):policy.check_projects(self.root,row,files,True)


if __name__ == '__main__':
    unittest.main()
