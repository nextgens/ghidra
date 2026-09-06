/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "architecture.hh"
#include "funcdata.hh"
#include "test.hh"

namespace ghidra {

/// Helper to load an architecture with a contained-call byte pattern.
/// The byte pattern at 0x1000 decodes (x86-64) as:
///   0x1000-0x1005: six NOPs (each 1 byte)
///   0x1006-0x100a: CALL 0x1001  (e8 f8 ff ff ff, relative offset -8)
///   0x100b:        RET         (c3)
/// The CALL at 0x1006 targets 0x1001 which is a previously visited
/// instruction start (a NOP), making it a "contained call".
static Architecture *loadContainedCallArch()

{
  string xml =
      "<binaryimage arch=\"x86:LE:64:default:gcc\">"
      "<bytechunk space=\"ram\" offset=\"0x1000\" readonly=\"true\">"
      "909090909090e8f8ffffffc3"
      "</bytechunk>"
      "</binaryimage>";
  ArchitectureCapability *capa = ArchitectureCapability::getCapability("xml");
  istringstream s(xml);
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());
  Architecture *glb = capa->buildArchitecture("", "", &cout);
  glb->init(store);
  glb->readLoaderSymbols();
  return glb;
}

/// Check if a Funcdata's p-code contains any CPUI_CALL operations.
static bool hasCallOp(const Funcdata &fd)

{
  PcodeOpTree::const_iterator iter;
  for(iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
    if ((*iter).second->code() == CPUI_CALL)
      return true;
  }
  return false;
}

/// Run followFlow on a contained-call pattern and return whether a CALL survived.
static bool runFlowAndCheckCall(Architecture *glb,ContainedCallMode mode)

{
  glb->contained_call_mode = mode;
  Scope *scope = glb->symboltab->getGlobalScope();
  Address entry(glb->getDefaultCodeSpace(), 0x1000);
  Funcdata fd("testfunc", "testfunc", scope, entry, (FunctionSymbol *)0, 0);
  fd.followFlow(entry, Address(glb->getDefaultCodeSpace(), 0x1010));
  return hasCallOp(fd);
}

//
// Three cspec parsing outcomes:
//   absent                         -> HEURISTIC
//   <containedcallbehavior mode="heuristic"/>   -> HEURISTIC
//   <containedcallbehavior mode="preserve"/>    -> PRESERVE
//

/// When <containedcallbehavior> is absent from the cspec, the mode must
/// default to CONTAINED_CALL_HEURISTIC (legacy behavior preserved).
TEST(containedcall_absent_defaults_heuristic) {
  Architecture *glb = loadContainedCallArch();
  // x86:LE:64:default:gcc cspec does not specify <containedcallbehavior>
  ASSERT(glb->contained_call_mode == CONTAINED_CALL_HEURISTIC);
  // Behavioral check: contained CALL is converted to BRANCH
  ASSERT(!runFlowAndCheckCall(glb,CONTAINED_CALL_HEURISTIC));
  delete glb;
}

/// When <containedcallbehavior mode="heuristic"/> is explicitly specified,
/// behavior must be identical to the default.
TEST(containedcall_mode_heuristic) {
  Architecture *glb = loadContainedCallArch();
  // Explicitly set to HEURISTIC (as the parser would for mode="heuristic")
  ASSERT(!runFlowAndCheckCall(glb,CONTAINED_CALL_HEURISTIC));
  delete glb;
}

/// When <containedcallbehavior mode="preserve"/> is specified, contained
/// CALLs must remain CPUI_CALL and not be rewritten to BRANCH.
TEST(containedcall_mode_preserve) {
  Architecture *glb = loadContainedCallArch();
  // Set to PRESERVE (as the parser would for mode="preserve")
  ASSERT(runFlowAndCheckCall(glb,CONTAINED_CALL_PRESERVE));
  delete glb;
}

} // End namespace ghidra
