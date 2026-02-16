/**
 * @name Check if annotations exist
 * @description Lists all annotations to see if they're extracted
 * @kind problem
 * @problem.severity recommendation
 * @id java/check-annotations
 */

import java

from Annotation ann
where ann.getType().getName().matches("%Mapping%")
select ann, "Annotation: " + ann.getType().getName() + " on " + ann.getAnnotatedElement()
