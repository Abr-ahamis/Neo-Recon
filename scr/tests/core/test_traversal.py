from __future__ import annotations

import unittest

from scr.core.resources import Access, Resource, ResourceStatus, TraversalLimits
from scr.engine.traversal import ResourceTraversal


def resource(kind: str, path: str, **kwargs: object) -> Resource:
    return Resource("smb", "127.0.0.1", 445, "tcp", kind, path.rsplit("/", 1)[-1] or "root",
                    path=path, **kwargs)


class TraversalTests(unittest.TestCase):
    def test_recurses_children_with_parent_depth_and_deduplication(self) -> None:
        root = resource("share", "backup", list_access=Access.YES)
        children = {
            "backup": [resource("directory", "backup/docs"), resource("directory", "backup/docs")],
            "backup/docs": [resource("directory", "backup/docs/archive")],
            "backup/docs/archive": [resource("file", "backup/docs/archive/credentials.txt",
                                              read_access=Access.YES)],
        }
        visited: list[str] = []

        def enumerate_one(item: Resource) -> list[Resource]:
            visited.append(item.path)
            return children.get(item.path, [])

        results = ResourceTraversal(TraversalLimits(max_workers=3)).traverse([root], enumerate_one)
        self.assertEqual(set(visited), set(children) | {"backup/docs/archive/credentials.txt"})
        file_resource = next(r for r in results.values() if r.resource_type == "file")
        self.assertEqual(file_resource.depth, 3)
        self.assertIn("backup/docs/archive", file_resource.parent or "")
        self.assertEqual(file_resource.status, ResourceStatus.SUCCESS)
        self.assertEqual(len(results), 4)

    def test_access_depth_and_resource_limits_stop_pivots(self) -> None:
        root = resource("share", "root")
        denied = resource("directory", "root/denied", list_access=Access.NO,
                          read_access=Access.NO, authentication_required=True)
        self.assertFalse(ResourceTraversal().offer(denied, root))
        traversal = ResourceTraversal(TraversalLimits(max_depth=2, max_files=1,
                                                       max_directories=1, max_tasks=3))
        first = resource("share", "share")
        self.assertTrue(traversal.offer(first))
        directory = resource("directory", "share/a")
        self.assertTrue(traversal.offer(directory, first))
        too_deep = resource("directory", "share/a/deep")
        self.assertFalse(traversal.offer(too_deep, directory))
        file1 = resource("file", "share/a/file1")
        self.assertTrue(traversal.offer(file1, directory))
        file2 = resource("file", "share/a/file2")
        self.assertFalse(traversal.offer(file2, directory))
        self.assertEqual(too_deep.status, ResourceStatus.SKIPPED)
        self.assertEqual(file2.status, ResourceStatus.SKIPPED)

    def test_failed_resource_does_not_block_other_resources(self) -> None:
        roots = [resource("share", "bad"), resource("share", "good")]

        def enumerate_one(item: Resource) -> list[Resource]:
            if item.path == "bad":
                raise RuntimeError("fixture failure")
            return []

        results = ResourceTraversal().traverse(roots, enumerate_one)
        self.assertEqual(results[roots[0].resource_id].status, ResourceStatus.FAILED)
        self.assertEqual(results[roots[1].resource_id].status, ResourceStatus.SUCCESS)


if __name__ == "__main__":
    unittest.main()
