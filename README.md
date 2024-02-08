# ⚠️ Quarkus XMLSec has moved to https://github.com/quarkiverse/quarkus-cxf/tree/main/extensions/santuario-xmlsec[Quarkus CXF]
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-2-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/quarkiverse/quarkus-xmlsec/build.yml?style=for-the-badge)
![Maven Central](https://img.shields.io/maven-central/v/io.quarkiverse.xmlsec/quarkus-xmlsec?style=for-the-badge)

The last version released under the old Maven coordinates `io.quarkiverse.xmlsec:quarkus-xmlsec` is 2.5.0 (based on Quarkus 3.7.0).

The new Maven coordinates (since Quarkus 3.8.0+) are as follows:

```xml
  ...
  <properties>
    <quarkus.version>3.8.0</quarkus.version><!-- or newer -->
  </properies>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>io.quarkus.platform</groupId>
        <artifactId>quarkus-cxf-bom</artifactId>
        <version>${quarkus.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>io.quarkiverse.cxf</groupId>
      <artifactId>quarkus-cxf-santuario-xmlsec</artifactId>
    </dependency>
  </dependencies>
  ...
```
