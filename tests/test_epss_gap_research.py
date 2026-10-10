"""Offline evidence-boundary tests. No live CVE, EPSS, KEV or vendor source downloads."""
import json
import math
import unittest
from datetime import date, timedelta

from eclipse_l2.epss_gap_research import _bucket, _rank, analyze_anchors, select_review_queue

DAYS = ("2025-04-01", "2025-05-01", "2025-06-01", "2026-07-01", "2026-08-01")


def sample():
    # Current and previous FIRST EPSS snapshots, alongside future KEV label set.
    # Keys are intentionally ordered differently each month; selectors must be stable.
    score = [
        {'CVE-2025-1001': .9, 'CVE-2025-1002': .15, 'CVE-2025-1003': .005},
        {'CVE-2025-1001': .8, 'CVE-2025-1002': .12, 'CVE-2025-1003': .04},
        {'CVE-2025-1001': .7, 'CVE-2025-1002': .10, 'CVE-2025-1003': .20},
        {'CVE-2025-1001': .6, 'CVE-2025-1002': .10, 'CVE-2025-1003': .40},
        {'CVE-2025-1001': .5, 'CVE-2025-1002': .20, 'CVE-2025-1003': .15},
    ]
    labels = {
        'CVE-2025-1002': date(2025, 5, 5),
        'CVE-2025-1003': date(2026, 7, 10),
        'CVE-2025-1004': date(2026, 7, 12),  # not scored at ANY anchor
        'CVE-2025-1005': date(2025, 4, 20),  # not scored at ANY anchor
    }
    return score, labels


class EpssGapTests(unittest.TestCase):
    def test_rank_excludes_asof_kev_and_rejects_bad_epss(self):
        out = _rank({'CVE-2025-1001': .7, 'CVE-2025-1002': .9}, {'CVE-2025-1002'})
        self.assertEqual(out,[(.7,'CVE-2025-1001')])
        with self.assertRaisesRegex(ValueError,"probabilities"):
            _rank({'CVE-2025-1001': math.nan},set())

    def test_80_20_increases_momentum_candidate_but_budget_exact(self):
        ranked = [(0.90, 'CVE-2025-1001'), (.80,'CVE-2025-1002'),
                  (.70,'CVE-2025-1003'), (.60,'CVE-2025-1004'), (.55,'CVE-2025-1005')]
        previous = {'CVE-2025-1001': .90, 'CVE-2025-1002': .79,
                    'CVE-2025-1003': .01, 'CVE-2025-1004': .59,
                    'CVE-2025-1005': .01}
        # Budget 5: slots 4+1; 1005 has greater month-to-month delta than 1004.
        self.assertEqual(select_review_queue(ranked,previous,5),
                         ['CVE-2025-1001','CVE-2025-1002','CVE-2025-1003',
                          'CVE-2025-1004','CVE-2025-1005'])
        # Budget 4: base 3, momentum 1 prefers 1005 over 1004.
        self.assertEqual(select_review_queue(ranked,previous,4),
                         ['CVE-2025-1001','CVE-2025-1002','CVE-2025-1003','CVE-2025-1005'])
        self.assertEqual(len(set(select_review_queue(ranked,previous,4))),4)

    def test_with_no_positive_trend_never_invents_zero_previous_epss(self):
        ranked=[(.8,'CVE-2025-1001'),(.3,'CVE-2025-1002')]
        self.assertEqual(select_review_queue(ranked,None,2),['CVE-2025-1001','CVE-2025-1002'])
        self.assertEqual(select_review_queue(ranked,{'CVE-2025-1001':.9},2),
                         ['CVE-2025-1001','CVE-2025-1002'])
        with self.assertRaises(ValueError):
            select_review_queue(ranked,None,0)

    def test_missing_kev_cohort_is_explicit_and_year_not_publication_claim(self):
        scored, labels = sample()
        r=analyze_anchors(scored,labels,dates=DAYS)
        self.assertEqual(len(r['monthly_anchors']),5)
        apr=r['monthly_anchors'][0]['evaluations']['30']
        self.assertEqual(apr['future_new_kev'],1)
        self.assertEqual(apr['rankable_future_kev'],0)
        self.assertEqual(apr['not_scored_on_asof'],1)
        july=r['monthly_anchors'][3]['evaluations']['30']
        self.assertEqual(july['future_new_kev'],2)
        self.assertEqual(july['rankable_future_kev'],1)
        self.assertEqual(july['not_scored_on_asof'],1)
        missed=r['full_unrankable_30_day_cohort']
        self.assertEqual(missed['missing_kev_anchor_events'],2)
        self.assertTrue(any(x['cve']=='CVE-2025-1004' for x in missed['cve_details']))
        self.assertTrue(all('publication' in x['availability_limit'] for x in missed['cve_details']))

    def test_cross_era_momentum_disabled(self):
        scored,labels=sample()
        r=analyze_anchors(scored,labels,dates=DAYS)
        self.assertFalse(r['monthly_anchors'][0]['paired_comparison'])
        self.assertTrue(r['monthly_anchors'][1]['paired_comparison'])
        self.assertFalse(r['monthly_anchors'][3]['paired_comparison'])
        self.assertTrue(r['monthly_anchors'][4]['paired_comparison'])
        self.assertEqual(r['results_paired_same_model_era']['ALL']['30']['paired_anchors'],3)

    def test_label_on_same_day_not_future_and_preexisting_kev_excluded(self):
        scored=[{'CVE-2025-1001':.7}, {'CVE-2025-1001':.8}]
        labels={'CVE-2025-1001':date(2025,4,1)}
        r=analyze_anchors(scored,labels,dates=DAYS[:2])
        self.assertEqual(r['monthly_anchors'][0]['already_kev_in_scored'],1)
        self.assertEqual(r['monthly_anchors'][0]['evaluations']['30']['future_new_kev'],0)

    def test_prior_anchor_disappearance_is_retrospective_evidence_not_feature(self):
        snapshots=[{'CVE-2025-1001':.2},{'CVE-2025-1002':.3}]
        labels={'CVE-2025-1001':date(2025,5,10)}
        r=analyze_anchors(snapshots,labels,dates=DAYS[:2])
        observed=r['full_unrankable_30_day_cohort']['cve_details'][0]
        self.assertEqual(observed['missing_class'],'PREVIOUSLY_SCORED_BUT_MISSING_NOW')
        self.assertTrue(observed['previously_scored_at_an_earlier_anchor'])
        self.assertIsNone(observed['first_later_scored_monthly_anchor'])

    def test_future_first_scored_anchor_is_not_alert_feature(self):
        snapshots=[{'CVE-2025-1002':.2},{'CVE-2025-1001':.3}]
        labels={'CVE-2025-1001':date(2025,4,12)}
        r=analyze_anchors(snapshots,labels,dates=DAYS[:2])
        p=r['full_unrankable_30_day_cohort']['cve_details'][0]
        self.assertEqual(p['missing_class'],'FIRST_SEEN_ON_LATER_MONTHLY_SNAPSHOT')
        self.assertEqual(p['first_later_scored_monthly_anchor'],'2025-05-01')

    def test_score_bucket_borders(self):
        self.assertEqual(_bucket(.00999),'<0.01')
        self.assertEqual(_bucket(.01),'0.01-<0.05')
        self.assertEqual(_bucket(.1),'0.10-<0.20')
        self.assertEqual(_bucket(.2),'>=0.20')


if __name__ == '__main__': unittest.main()
