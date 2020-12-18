/*

The following options and flags need to be available

FLAG
-----
-s --standalone : This should signal that we run in standalone mode. Any required repair scripts need to be downloaded from git

ARGUMENT
--------
Either pass over a single action or many seperated by a comma.
Each action needs the nto be verified for its existens on git/filesystem
If the action does exists it gets executed

OPTIONS
--------
 -d --dir : The directory in which action-implementations are stored. Can be used for testing of scripts as well.
            The standalone flag is necessary to be set as well


*/