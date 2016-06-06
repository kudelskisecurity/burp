from burp.models.enums import ScanStatus
from burp.models.scan.active import Request, Scan, ScanNotFoundError
from test import TestBase


class TestScanPassive(TestBase):
    def test_scan_active_get_all(self):
        set(self.burp.scan.active.get())

    def test_scan_active_get_unknown_id(self):
        self.assertRaises(ScanNotFoundError,
                          self.burp.scan.active.get,
                          Scan(
                              id=9999999,
                              errors=0,
                              insertion_point_count=0,
                              request_count=0,
                              status=ScanStatus.FINISHED,
                              percent_complete=100,
                              issues=tuple(),  # TODO add test issue
                          ))

    def test_scan_active_get_delete_unknown_id(self):
        self.assertRaises(ScanNotFoundError,
                          self.burp.scan.active.delete,
                          Scan(
                              id=9999999,
                              errors=0,
                              insertion_point_count=0,
                              request_count=0,
                              status=ScanStatus.FINISHED,
                              percent_complete=100,
                              issues=tuple(),  # TODO add test issue
                          ))

    def test_scan_active(self):
        old_active = set(self.burp.scan.active.get())
        self.burp.scan.active.post(Request(
            host=self.target,
            port=80,
            use_https=False,
            request=b'GET / HTTP/1.1\n'
                    b'Host: perdu.com\n'
                    b'\n'
                    b'lost?',
        ))

        new_active = set(self.burp.scan.active.get())
        self.assertEqual(len(old_active) + 1, len(new_active))

        diff_scans = (new_active - old_active)
        self.assertEqual(len(diff_scans), 1)

        new_scan = diff_scans.pop()
        ret_new_scan = next(self.burp.scan.active.get(new_scan))
        self.assertEqual(new_scan, ret_new_scan)

        self.burp.scan.active.delete(new_scan)
        new_after_delete_active = set(self.burp.scan.active.get())
        self.assertSetEqual(old_active, new_after_delete_active)
