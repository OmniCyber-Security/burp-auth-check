plugins {
    java
    id("com.gradleup.shadow") version "9.6.1"
}

group = "com.omnicybersecurity"
version = "1.1.0"

repositories {
    mavenCentral()
}

val montoyaVersion = "2026.7"

// Identifies the exact build at runtime. CI provides the sha; a local build
// falls back to git, and to "unknown" outside a checkout.
val buildCommit: Provider<String> =
    providers.environmentVariable("GITHUB_SHA").map { it.take(7) }
        .orElse(
            providers.exec {
                commandLine("git", "rev-parse", "--short", "HEAD")
                isIgnoreExitValue = true
            }.standardOutput.asText.map { it.trim() }
        )
        .map { it.ifBlank { "unknown" } }
        .orElse("unknown")
val groovyVersion = "5.1.0"

dependencies {
    // Provided by Burp at runtime -- must NOT be bundled.
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")

    // Bundled: the scripting engine testers write auth-maintenance scripts in.
    implementation("org.apache.groovy:groovy:$groovyVersion")
    implementation("org.apache.groovy:groovy-json:$groovyVersion")

    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testCompileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testRuntimeOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}

java {
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    // Burp ships its own JRE; 17 is the safe floor for current Burp releases.
    options.release = 17
    options.encoding = "UTF-8"
    options.compilerArgs.add("-Xlint:all,-serial,-this-escape")
}

tasks.shadowJar {
    archiveBaseName = "burp-auth-check"
    archiveClassifier = ""
    // INCLUDE lets the service/extension-module transformers see every duplicate
    // before merging; EXCLUDE would silently drop all but the first.
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    // Groovy's extension modules live in per-jar descriptors that must be
    // concatenated, not overwritten, or JsonSlurper's DGM methods vanish.
    mergeGroovyExtensionModules()
    mergeServiceFiles()
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    exclude("META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/INDEX.LIST")
    exclude("module-info.class", "META-INF/versions/*/module-info.class")
    manifest {
        attributes(
            "Implementation-Title" to "Burp Auth Check",
            "Implementation-Version" to project.version.toString(),
            "Implementation-Commit" to buildCommit.get(),
        )
    }
}

tasks.jar {
    // The thin jar is useless to Burp; keep `build` producing the loadable one.
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
