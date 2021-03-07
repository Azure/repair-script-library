//! The essential objective of this crate is to provide an API for copying
//! directories and their contents in a straightforward and predictable way.
//! See the documentation of the `copy_dir` function for more info.

extern crate walkdir;

use std::fs;
use std::path::Path;
use std::io::{Error, ErrorKind, Result};

macro_rules! push_error {
    ($expr:expr, $vec:ident) => {
        match $expr {
            Err(e) => $vec.push(e),
            Ok(_) => (),
        }
    };
}

macro_rules! make_err {
    ($text:expr, $kind:expr) => {
        Error::new($kind, $text)
    };

    ($text:expr) => {
        make_err!($text, ErrorKind::Other)
    };
}

/// Copy a directory and its contents
///
/// Unlike e.g. the `cp -r` command, the behavior of this function is simple
/// and easy to understand. The file or directory at the source path is copied
/// to the destination path. If the source path points to a directory, it will
/// be copied recursively with its contents.
///
/// # Errors
///
/// * It's possible for many errors to occur during the recursive copy
///   operation. These errors are all returned in a `Vec`. They may or may
///   not be helpful or useful.
/// * If the source path does not exist.
/// * If the destination path exists.
/// * If something goes wrong with copying a regular file, as with
///   `std::fs::copy()`.
/// * If something goes wrong creating the new root directory when copying
///   a directory, as with `std::fs::create_dir`.
/// * If you try to copy a directory to a path prefixed by itself i.e.
///   `copy_dir(".", "./foo")`. See below for more details.
///
/// # Caveats/Limitations
///
/// I would like to add some flexibility around how "edge cases" in the copying
/// operation are handled, but for now there is no flexibility and the following
/// caveats and limitations apply (not by any means an exhaustive list):
///
/// * You cannot currently copy a directory into itself i.e.
///   `copy_dir(".", "./foo")`. This is because we are recursively walking
///   the directory to be copied *while* we're copying it, so in this edge
///   case you get an infinite recursion. Fixing this is the top of my list
///   of things to do with this crate.
/// * Hard links are not accounted for, i.e. if more than one hard link
///   pointing to the same inode are to be copied, the data will be copied
///   twice.
/// * Filesystem boundaries may be crossed.
/// * Symbolic links will be copied, not followed.
pub fn copy_dir<Q: AsRef<Path>, P: AsRef<Path>>(from: P, to: Q)
                                                -> Result<Vec<Error>> {
    if !from.as_ref().exists() {
        return Err(make_err!(
            "source path does not exist",
            ErrorKind::NotFound
        ));

    } else if to.as_ref().exists() {
        return Err(make_err!(
            "target path exists",
            ErrorKind::AlreadyExists
        ))
    }

    let mut errors = Vec::new();

    // copying a regular file is EZ
    if from.as_ref().is_file() {
        return fs::copy(&from, &to).map(|_| Vec::new() );
    }

    try!(fs::create_dir(&to));

    // The approach taken by this code (i.e. walkdir) will not gracefully
    // handle copying a directory into itself, so we're going to simply
    // disallow it by checking the paths. This is a thornier problem than I
    // wish it was, and I'd like to find a better solution, but for now I
    // would prefer to return an error rather than having the copy blow up
    // in users' faces. Ultimately I think a solution to this will involve
    // not using walkdir at all, and might come along with better handling
    // of hard links.
    let target_is_under_source = try!(
        from.as_ref()
            .canonicalize()
            .and_then(|fc| to.as_ref().canonicalize().map(|tc| (fc, tc) ))
            .map(|(fc, tc)| tc.starts_with(fc) )
    );

    if target_is_under_source {
        try!(fs::remove_dir(&to));

        return Err(make_err!(
            "cannot copy to a path prefixed by the source path"
        ));
    }

    for entry in walkdir::WalkDir::new(&from)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok() ) {

        let relative_path = match entry.path().strip_prefix(&from) {
            Ok(rp) => rp,
            Err(_) => panic!("strip_prefix failed; this is a probably a bug in copy_dir"),
        };

        let target_path = {
            let mut target_path = to.as_ref().to_path_buf();
            target_path.push(relative_path);
            target_path
        };

        let source_metadata = match entry.metadata() {
            Err(_) => {
                errors.push(make_err!(format!(
                    "walkdir metadata error for {:?}",
                    entry.path()
                )));

                continue
            },

            Ok(md) => md,
        };

        if source_metadata.is_dir() {
            push_error!(fs::create_dir(&target_path), errors);
            push_error!(
                fs::set_permissions(
                    &target_path,
                    source_metadata.permissions()
                ),
                errors
            );

        } else {
            push_error!(fs::copy(entry.path(), &target_path), errors);
        }
    }

    Ok(errors)
}

#[cfg(test)]
mod tests {
    #![allow(unused_variables)]

    extern crate std;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    extern crate walkdir;
    extern crate tempdir;

    #[test]
    fn single_file() {
        let file = File("foo.file");
        assert_we_match_the_real_thing(&file, true, None);
    }

    #[test]
    fn directory_with_file() {
        let dir = Dir("foo", vec![
            File("bar"),
            Dir("baz", vec![
                File("quux"),
                File("fobe")
            ])
        ]);
        assert_we_match_the_real_thing(&dir, true, None);
    }

    #[test]
    fn source_does_not_exist() {
        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();
        let source_path = base_dir.as_ref().join("noexist.file");
        match super::copy_dir(&source_path, "dest.file") {
            Ok(_) => panic!("expected Err"),
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => (),
                _ => panic!("expected kind NotFound"),
            },
        }
    }

    #[test]
    fn target_exists() {
        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();
        let source_path = base_dir.as_ref().join("exist.file");
        let target_path = base_dir.as_ref().join("exist2.file");

        {
            fs::File::create(&source_path).unwrap();
            fs::File::create(&target_path).unwrap();
        }

        match super::copy_dir(&source_path, &target_path) {
            Ok(_) => panic!("expected Err"),
            Err(err) => match err.kind() {
                std::io::ErrorKind::AlreadyExists => (),
                _ => panic!("expected kind AlreadyExists")
            }
        }
    }

    #[test]
    fn attempt_copy_under_self() {
        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();
        let dir = Dir("foo", vec![
            File("bar"),
            Dir("baz", vec![
                File("quux"),
                File("fobe")
            ])
        ]);
        dir.create(&base_dir).unwrap();

        let from = base_dir.as_ref().join("foo");
        let to = from.as_path().join("beez");

        let copy_result = super::copy_dir(&from, &to);
        assert!(copy_result.is_err());

        let copy_err = copy_result.unwrap_err();
        assert_eq!(copy_err.kind(), std::io::ErrorKind::Other);
    }

    // utility stuff below here

    enum DirMaker<'a> {
        Dir(&'a str, Vec<DirMaker<'a>>),
        File(&'a str),
    }

    use self::DirMaker::*;

    impl<'a> DirMaker<'a> {
        fn create<P: AsRef<Path>>(&self, base: P) -> std::io::Result<()> {
            match *self {
                Dir(ref name, ref contents) => {
                    let path = base.as_ref().join(name);
                    try!(fs::create_dir(&path));

                    for thing in contents {
                        try!(thing.create(&path));
                    }
                },

                File(ref name) => {
                    let path = base.as_ref().join(name);
                    try!(fs::File::create(path));
                }
            }

            Ok(())
        }

        fn name(&self) -> &str {
            match *self {
                Dir(name, _) => name,
                File(name) => name,
            }
        }
    }

    fn assert_dirs_same<P: AsRef<Path>>(a: P, b: P) {
        let mut wa = walkdir::WalkDir::new(a.as_ref()).into_iter();
        let mut wb = walkdir::WalkDir::new(b.as_ref()).into_iter();

        loop {
            let o_na = wa.next();
            let o_nb = wb.next();

            if o_na.is_some() && o_nb.is_some() {
                let r_na = o_na.unwrap();
                let r_nb = o_nb.unwrap();

                if r_na.is_ok() && r_nb.is_ok() {
                    let na = r_na.unwrap();
                    let nb = r_nb.unwrap();

                    assert_eq!(
                        na.path().strip_prefix(a.as_ref()),
                        nb.path().strip_prefix(b.as_ref())
                    );

                    assert_eq!(na.file_type(), nb.file_type());

                    // TODO test permissions
                }

            } else if o_na.is_none() && o_nb.is_none() {
                return
            } else {
                assert!(false);
            }
        }
    }

    fn assert_we_match_the_real_thing(dir: &DirMaker,
                                      explicit_name: bool,
                                      o_pre_state: Option<&DirMaker>) {
        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();

        let source_dir = base_dir.as_ref().join("source");
        let our_dir = base_dir.as_ref().join("ours");
        let their_dir = base_dir.as_ref().join("theirs");

        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&our_dir).unwrap();
        fs::create_dir(&their_dir).unwrap();

        dir.create(&source_dir).unwrap();
        let source_path = source_dir.as_path().join(dir.name());

        let (our_target, their_target) = if explicit_name {
            (
                our_dir.as_path().join(dir.name()),
                their_dir.as_path().join(dir.name())
            )
        } else {
            (our_dir.clone(), their_dir.clone())
        };

        if let Some(pre_state) = o_pre_state {
            pre_state.create(&our_dir).unwrap();
            pre_state.create(&their_dir).unwrap();
        }

        let we_good = super::copy_dir(&source_path, &our_target).is_ok();

        let their_status = Command::new("cp")
            .arg("-r")
            .arg(source_path.as_os_str())
            .arg(their_target.as_os_str())
            .status()
            .unwrap();

        let tree_output = Command::new("tree")
            .arg(base_dir.as_ref().as_os_str())
            .output()
            .unwrap();

        println!("{}",
                 std::str::from_utf8(tree_output.stdout.as_slice()).unwrap());

        // TODO any way to ask cp whether it worked or not?
        // portability?
        // assert_eq!(we_good, their_status.success());
        assert_dirs_same(&their_dir, &our_dir);
    }

    #[test]
    fn dir_maker_and_assert_dirs_same_baseline() {
        let dir = Dir(
            "foobar",
            vec![
                File("bar"),
                Dir("baz", Vec::new())
            ]
        );

        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();

        let a_path = base_dir.as_ref().join("a");
        let b_path = base_dir.as_ref().join("b");

        fs::create_dir(&a_path).unwrap();
        fs::create_dir(&b_path).unwrap();

        dir.create(&a_path).unwrap();
        dir.create(&b_path).unwrap();

        assert_dirs_same(&a_path, &b_path);
    }

    #[test]
    #[should_panic]
    fn assert_dirs_same_properly_fails() {
        let dir = Dir(
            "foobar",
            vec![
                File("bar"),
                Dir("baz", Vec::new())
            ]
        );

        let dir2 = Dir(
            "foobar",
            vec![
                File("fobe"),
                File("beez")
            ]
        );

        let base_dir = tempdir::TempDir::new("copy_dir_test").unwrap();

        let a_path = base_dir.as_ref().join("a");
        let b_path = base_dir.as_ref().join("b");

        fs::create_dir(&a_path).unwrap();
        fs::create_dir(&b_path).unwrap();

        dir.create(&a_path).unwrap();
        dir2.create(&b_path).unwrap();

        assert_dirs_same(&a_path, &b_path);
    }

}
