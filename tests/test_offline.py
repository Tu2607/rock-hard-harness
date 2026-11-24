"""parsers.offline on a minimal hand-built ARF-shaped document (synthetic,
not oscap output): the shape is what matters here, the real-scan behaviour
was checked against Oracle Linux 8/9, RHEL 9 and Ubuntu 22.04/24.04 scans."""

from lxml import etree

from rockhard.parsers.offline import not_really_applicable, offline_gaps

DOC = """
<root xmlns:x="http://checklists.nist.gov/xccdf/1.2"
      xmlns:cpe="http://cpe.mitre.org/language/2.0"
      xmlns:res="http://oval.mitre.org/XMLSchema/oval-results-5"
      xmlns:def="http://oval.mitre.org/XMLSchema/oval-definitions-5"
      xmlns:sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
      xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
      xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
  <x:Benchmark>
    <cpe:platform-specification>
      <cpe:platform id="machine"><cpe:logical-test operator="AND" negate="false">
        <cpe:check-fact-ref id-ref="oval:t:def:machine"/></cpe:logical-test></cpe:platform>
      <cpe:platform id="x86"><cpe:logical-test operator="AND" negate="false">
        <cpe:check-fact-ref id-ref="oval:t:def:arch"/></cpe:logical-test></cpe:platform>
      <cpe:platform id="nokernel"><cpe:logical-test operator="AND" negate="false">
        <cpe:check-fact-ref id-ref="oval:t:def:kernel"/></cpe:logical-test></cpe:platform>
    </cpe:platform-specification>
    <x:Group id="g"><x:platform idref="#machine"/>
      <x:Rule id="r_sniffer"><x:check><x:check-content-ref name="oval:t:def:sniffer"/></x:check></x:Rule>
      <x:Rule id="r_arch"><x:platform idref="#x86"/><x:check><x:check-content-ref name="oval:t:def:file"/></x:check></x:Rule>
      <x:Rule id="r_nokernel"><x:platform idref="#x86"/><x:platform idref="#nokernel"/>
        <x:check><x:check-content-ref name="oval:t:def:file"/></x:check></x:Rule>
      <x:Rule id="r_plain"><x:check><x:check-content-ref name="oval:t:def:file"/></x:check></x:Rule>
    </x:Group>
  </x:Benchmark>
  <res:oval_results>
    <def:oval_definitions>
      <def:definitions>
        <def:definition id="oval:t:def:machine"><def:criteria><def:criterion test_ref="oval:t:tst:file"/></def:criteria></def:definition>
        <def:definition id="oval:t:def:arch"><def:criteria><def:criterion test_ref="oval:t:tst:uname"/></def:criteria></def:definition>
        <def:definition id="oval:t:def:kernel"><def:criteria><def:criterion test_ref="oval:t:tst:file"/></def:criteria></def:definition>
        <def:definition id="oval:t:def:sniffer"><def:criteria><def:criterion test_ref="oval:t:tst:iface"/></def:criteria></def:definition>
        <def:definition id="oval:t:def:file"><def:criteria><def:criterion test_ref="oval:t:tst:file"/></def:criteria></def:definition>
      </def:definitions>
      <def:tests>
        <unix:uname_test id="oval:t:tst:uname"><unix:object object_ref="oval:t:obj:uname"/></unix:uname_test>
        <unix:interface_test id="oval:t:tst:iface"><unix:object object_ref="oval:t:obj:iface"/></unix:interface_test>
        <ind:textfilecontent54_test id="oval:t:tst:file"><ind:object object_ref="oval:t:obj:file"/></ind:textfilecontent54_test>
      </def:tests>
      <def:objects>
        <unix:uname_object id="oval:t:obj:uname"/>
        <unix:interface_object id="oval:t:obj:iface"/>
        <ind:textfilecontent54_object id="oval:t:obj:file"/>
      </def:objects>
    </def:oval_definitions>
    <res:results><res:system>
      <res:definitions>
        <res:definition definition_id="oval:t:def:machine" result="true"/>
        <res:definition definition_id="oval:t:def:arch" result="not applicable"/>
        <res:definition definition_id="oval:t:def:kernel" result="false"/>
        <res:definition definition_id="oval:t:def:sniffer" result="not applicable"/>
        <res:definition definition_id="oval:t:def:file" result="true"/>
      </res:definitions>
      <sc:oval_system_characteristics><sc:collected_objects>
        <sc:object id="oval:t:obj:uname" flag="not applicable"/>
        <sc:object id="oval:t:obj:iface" flag="not applicable"/>
        <sc:object id="oval:t:obj:file" flag="complete"/>
      </sc:collected_objects></sc:oval_system_characteristics>
    </res:system></res:results>
  </res:oval_results>
</root>
"""


def _root():
    return etree.fromstring(DOC.encode())


def test_offline_gaps_follow_checks_and_platforms():
    gaps = offline_gaps(_root())
    assert gaps == {"r_sniffer": ["interface"], "r_arch": ["uname"], "r_nokernel": ["uname"]}


def test_only_rules_a_skipped_probe_made_notapplicable():
    # r_nokernel is ruled out by a platform that evaluated false on its own.
    assert not_really_applicable(_root()) == {"r_sniffer", "r_arch"}
