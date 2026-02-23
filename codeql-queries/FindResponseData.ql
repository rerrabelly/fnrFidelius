/**
 * @name Find what data types are returned by REST endpoints
 * @kind problem
 * @id custom/find-response-data
 * @problem.severity recommendation
 */

import java

/**
 * Spring REST controller class
 */
class RestControllerClass extends Class {
  RestControllerClass() {
    this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RestController")
  }
}

/**
 * HTTP request mapping annotations
 */
predicate isRequestMappingAnnotation(Annotation a) {
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping") or
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping") or
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PostMapping") or
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PutMapping") or
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "DeleteMapping") or
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PatchMapping")
}

/**
 * Extract HTTP path from annotation
 */
string getHttpPath(Annotation a) {
  exists(Expr pathValue |
    (pathValue = a.getValue("value") or pathValue = a.getValue("path")) and
    result = pathValue.(CompileTimeConstantExpr).getStringValue()
  )
  or
  not exists(a.getValue("value")) and
  not exists(a.getValue("path")) and
  result = ""
}

/**
 * Get the type that ResponseEntity wraps (e.g., ResponseEntity<Account> -> Account)
 */
RefType getResponseEntityType(Type t) {
  exists(ParameterizedType pt |
    pt = t and
    pt.getSourceDeclaration().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    result = pt.getTypeArgument(0)
  )
}

/**
 * Get all fields from a class (for reporting what data is exposed)
 */
string getClassFields(RefType type) {
  result = concat(Field f |
    f.getDeclaringType() = type |
    f.getName(), ", " order by f.getName()
  )
}

from Method m, Annotation mapping, RefType controller, string path, Type returnType, string dataExposed
where
  controller instanceof RestControllerClass and
  m.getDeclaringType() = controller and
  mapping = m.getAnAnnotation() and
  isRequestMappingAnnotation(mapping) and
  path = getHttpPath(mapping) and
  returnType = m.getReturnType() and
  (
    // Case 1: Returns ResponseEntity<SomeType>
    exists(RefType innerType |
      innerType = getResponseEntityType(returnType) and
      if innerType.getName() != "?" then
        dataExposed = "Type: " + innerType.getName() + " | Fields: [" + getClassFields(innerType) + "]"
      else
        dataExposed = "Type: ResponseEntity<?> (wildcard)"
    )
    or
    // Case 2: Returns a direct type (with @ResponseBody)
    (
      not exists(getResponseEntityType(returnType)) and
      exists(Annotation a | a = m.getAnAnnotation() and a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ResponseBody")) and
      dataExposed = "Type: " + returnType.getName() + " (direct @ResponseBody)"
    )
    or
    // Case 3: Returns void or other
    (
      not exists(getResponseEntityType(returnType)) and
      not exists(Annotation a | a = m.getAnAnnotation() and a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ResponseBody")) and
      dataExposed = "Type: " + returnType.getName() + " (no ResponseEntity wrapper)"
    )
  )
select m,
  "Endpoint: " + controller.getName() + "." + m.getName() + "() | " +
  "Path: " + path + " | " +
  dataExposed + " | " +
  "at " + m.getLocation().getFile().getBaseName() + ":" + m.getLocation().getStartLine()
