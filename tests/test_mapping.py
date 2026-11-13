import csv
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch
import mapping as m

ROOT=Path(__file__).resolve().parents[1]
class MappingTests(unittest.TestCase):
    def setUp(self):
        self.scope=m.load_scope(ROOT/'data/scope.json')
        with (ROOT/'data/observations.csv').open() as f: self.rows=list(csv.DictReader(f))
    def test_expected_temporal_relations(self):
        g=m.build_graph(self.rows,self.scope)
        self.assertEqual(len(g['relationships']),4)
        self.assertFalse(any('archive.lab.test' in (x['from'],x['to']) for x in g['relationships']))
        shared=next(x for x in g['relationships'] if x['relation']=='shared_certificate')
        self.assertEqual(shared['evidence_ids'],['C01','C02'])
        self.assertEqual(shared['overlap_start'],'2024-01-05')
        self.assertEqual(shared['overlap_end'],'2024-01-10')
    def test_scope_exact_no_suffix_bypass(self):
        for bad in ['portal.lab.test.evil.test','evilportal.lab.test','outside.test']:
            rows=deepcopy(self.rows); rows[0]['domain']=bad
            with self.assertRaises(ValueError): m.build_graph(rows,self.scope)
    def test_invalid_observations(self):
        for field,value in [('value','8.8.8.8'),('first_seen','2025-01-01'),('last_seen','not-a-date'),('kind','dns_txt'),('source','')]:
            rows=deepcopy(self.rows); rows[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError): m.build_graph(rows,self.scope)
    def test_duplicate_ids(self):
        with self.assertRaises(ValueError): m.build_graph(self.rows+[self.rows[0]],self.scope)
    def test_deterministic_and_offline(self):
        with patch('socket.socket',side_effect=AssertionError('network')):
            g=m.build_graph(self.rows,self.scope)
        self.assertEqual(g,m.build_graph(list(reversed(self.rows)),self.scope))
        self.assertIn('D01 2024-01-01..2024-01-10',m.to_dot(g))
    def test_boundary_single_day(self):
        rows=deepcopy(self.rows[:2]); rows[1]['first_seen']='2024-01-10'
        self.assertEqual(m.build_graph(rows,self.scope)['relationships'][0]['overlap_end'],'2024-01-10')
    def test_fingerprint_validation(self):
        rows=deepcopy(self.rows); rows[-1]['value']='not-a-hash'
        with self.assertRaises(ValueError): m.build_graph(rows,self.scope)

class DateNormalizationTests(unittest.TestCase):
    def test_compact_iso_dates_normalized_before_comparison(self):
        scope={'allowed_domains':['a.lab.test','b.lab.test'],'dataset_kind':'synthetic'}
        common={'kind':'dns_a','value':'192.0.2.1','source':'synthetic'}
        rows=[{**common,'id':'A','domain':'a.lab.test','first_seen':'20240101','last_seen':'20240110'},
              {**common,'id':'B','domain':'b.lab.test','first_seen':'2024-01-05','last_seen':'2024-01-12'}]
        relation=m.build_graph(rows,scope)['relationships'][0]
        self.assertEqual(relation['overlap_start'],'2024-01-05')
        self.assertEqual(relation['overlap_end'],'2024-01-10')

if __name__=='__main__': unittest.main()
