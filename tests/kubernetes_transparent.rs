//! Disposable Cilium enforcement test for the transparent-proxy Helm policy.
//!
//! Run against a Cilium-capable cluster, for example the documented kind
//! fixture, with:
//! `AV_K8S_E2E_CONTEXT=kind-av-transparent-e2e cargo test --test kubernetes_transparent -- --ignored`.
//! It uses a pinned BusyBox image and synthetic local endpoints only.

use std::{
    error::Error,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const BUSYBOX_IMAGE: &str = "docker.io/library/busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028";

#[test]
#[ignore = "requires AV_K8S_E2E_CONTEXT and a Cilium-capable Kubernetes cluster"]
fn transparent_proxy_policy_blocks_direct_tcp_and_udp_bypass() -> Result<(), Box<dyn Error>> {
    let context = std::env::var("AV_K8S_E2E_CONTEXT")?;
    let namespace = format!(
        "av-transparent-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
    );
    let result = run_fixture(&context, &namespace);
    let _ = kubectl(
        &context,
        ["delete", "namespace", &namespace, "--wait=false"],
        None,
    );
    result
}

fn run_fixture(context: &str, namespace: &str) -> Result<(), Box<dyn Error>> {
    eprintln!("k8s-e2e: create namespace");
    kubectl(context, ["create", "namespace", namespace], None)?;
    let values = tempfile::NamedTempFile::new()?;
    std::fs::write(
        values.path(),
        format!(
            r#"
controlPlane:
  mode: managed
  existingDatabaseSecret:
    name: synthetic-database
    key: database-url
  initialOwnerOidcSubject: oidc:synthetic
transparentProxy:
  enabled: true
  port: 14323
  proxyUrl: https://av-av-proxy.{namespace}.svc.cluster.local:14323
  transportTlsSecret:
    name: synthetic-proxy-transport
  caSecret:
    name: synthetic-proxy-ca
  networkPolicy:
    enabled: true
    workloadSelector:
      matchLabels:
        app.kubernetes.io/part-of: transparent-test
    proxyClientPodSelector:
      matchLabels:
        app.kubernetes.io/part-of: transparent-test
  cilium:
    enabled: true
    workloadSelector:
      matchLabels:
        k8s:app.kubernetes.io/part-of: transparent-test
"#
        ),
    )?;
    let rendered = command_output(
        Command::new("helm")
            .args(["template", "av", "chart/av", "--namespace", namespace, "-f"])
            .arg(values.path()),
    )?;
    eprintln!("k8s-e2e: render policies");
    let policies = rendered
        .split("\n---\n")
        .filter(|document| {
            document.contains("kind: NetworkPolicy")
                || document.contains("kind: CiliumNetworkPolicy")
        })
        .collect::<Vec<_>>()
        .join("\n---\n");
    if policies.is_empty() {
        return Err("Helm did not render transparent proxy policies".into());
    }
    kubectl(
        context,
        ["apply", "-n", namespace, "-f", "-"],
        Some(&policies),
    )?;
    eprintln!("k8s-e2e: apply proxy");
    kubectl(
        context,
        ["apply", "-n", namespace, "-f", "-"],
        Some(&synthetic_proxy()),
    )?;
    eprintln!("k8s-e2e: proxy ready");
    kubectl(
        context,
        [
            "wait",
            "-n",
            namespace,
            "--for=condition=Ready",
            "pod/av",
            "--timeout=90s",
        ],
        None,
    )?;
    eprintln!("k8s-e2e: client ready");
    kubectl(
        context,
        ["apply", "-n", namespace, "-f", "-"],
        Some(&client_pod()),
    )?;
    eprintln!("k8s-e2e: proxy reachable");
    kubectl(
        context,
        [
            "wait",
            "-n",
            namespace,
            "--for=condition=Ready",
            "pod/client",
            "--timeout=90s",
        ],
        None,
    )?;

    // The exact Service and named proxy port rendered by the Helm chart work.
    kubectl(
        context,
        [
            "exec",
            "-n",
            namespace,
            "client",
            "--",
            "nc",
            "-z",
            "-w",
            "5",
            &format!("av-av-proxy.{namespace}.svc.cluster.local"),
            "14323",
        ],
        None,
    )?;

    // No broad TCP/443 egress rule exists. A successful connection would be a
    // policy regression rather than an expected lack of Internet access.
    let direct_tcp = kubectl_status(
        context,
        [
            "exec", "-n", namespace, "client", "--", "nc", "-z", "-w", "3", "1.1.1.1", "443",
        ],
        None,
    )?;
    if direct_tcp.success() {
        return Err("selected workload reached direct TCP/443".into());
    }
    eprintln!("k8s-e2e: direct TCP blocked");

    // UDP tools report success after a local send, so prove non-delivery with
    // a controlled UDP receiver rather than trusting the sender exit code.
    kubectl(
        context,
        ["apply", "-n", namespace, "-f", "-"],
        Some(&udp_target_pod()),
    )?;
    eprintln!("k8s-e2e: UDP target ready");
    kubectl(
        context,
        [
            "wait",
            "-n",
            namespace,
            "--for=condition=Ready",
            "pod/udp-target",
            "--timeout=90s",
        ],
        None,
    )?;
    let target_ip = command_output(
        Command::new("kubectl")
            .args([
                "--context",
                context,
                "-n",
                namespace,
                "get",
                "pod",
                "udp-target",
                "-o",
            ])
            .arg("jsonpath={.status.podIP}"),
    )?;
    kubectl(
        context,
        [
            "exec",
            "-n",
            namespace,
            "client",
            "--",
            "sh",
            "-ec",
            &format!("printf blocked-udp | nc -u -w 1 {} 14443", target_ip.trim()),
        ],
        None,
    )?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    let received = kubectl_status(
        context,
        [
            "exec",
            "-n",
            namespace,
            "udp-target",
            "--",
            "sh",
            "-ec",
            "test ! -s /tmp/received",
        ],
        None,
    )?;
    if !received.success() {
        return Err("selected workload delivered direct UDP traffic".into());
    }
    eprintln!("k8s-e2e: direct UDP blocked");
    Ok(())
}

fn kubectl<const N: usize>(
    context: &str,
    args: [&str; N],
    stdin: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let mut command = Command::new("kubectl");
    command.arg("--context").arg(context).args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command_output_with_stdin(&mut command, stdin)
}

fn kubectl_status<const N: usize>(
    context: &str,
    args: [&str; N],
    stdin: Option<&str>,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    let mut command = Command::new("kubectl");
    command.arg("--context").arg(context).args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = command.spawn()?;
    if let (Some(input), Some(mut process_stdin)) = (stdin, child.stdin.take()) {
        process_stdin.write_all(input.as_bytes())?;
    }
    Ok(child.wait()?)
}

fn command_output(command: &mut Command) -> Result<String, Box<dyn Error>> {
    command_output_with_stdin(command, None)
}

fn command_output_with_stdin(
    command: &mut Command,
    stdin: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(input), Some(mut process_stdin)) = (stdin, child.stdin.take()) {
        process_stdin.write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn synthetic_proxy() -> String {
    format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: av
  labels:
    app.kubernetes.io/name: av
    app.kubernetes.io/instance: av
spec:
  containers:
    - name: proxy
      image: {BUSYBOX_IMAGE}
      command: ["httpd", "-f", "-p", "14323"]
      ports:
        - name: proxy
          containerPort: 14323
---
apiVersion: v1
kind: Service
metadata:
  name: av-av-proxy
spec:
  selector:
    app.kubernetes.io/name: av
    app.kubernetes.io/instance: av
  ports:
    - name: proxy
      port: 14323
      targetPort: proxy
"#
    )
}

fn client_pod() -> String {
    format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: client
  labels:
    app.kubernetes.io/part-of: transparent-test
spec:
  containers:
    - name: client
      image: {BUSYBOX_IMAGE}
      command: ["sleep", "300"]
"#
    )
}

fn udp_target_pod() -> String {
    format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: udp-target
  labels:
    app: udp-target
spec:
  containers:
    - name: receiver
      image: {BUSYBOX_IMAGE}
      command: ["sh", "-ec", "rm -f /tmp/received; nc -u -l -p 14443 > /tmp/received"]
"#
    )
}
