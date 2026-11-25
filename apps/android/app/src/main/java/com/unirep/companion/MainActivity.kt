package com.unirep.companion

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { ReforgeApp() }
    }
}

private suspend fun apiCall(base: String, token: String, method: String, route: String,
                            body: JSONObject? = null): JSONObject = withContext(Dispatchers.IO) {
    val connection = (URL(base.trimEnd('/') + route).openConnection() as HttpURLConnection)
    try {
        connection.requestMethod = method
        connection.connectTimeout = 8000
        connection.readTimeout = 15000
        connection.setRequestProperty("Authorization", "Bearer $token")
        connection.setRequestProperty("Accept", "application/json")
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        }
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() } ?: "{}"
        if (status !in 200..299) throw IllegalStateException("HTTP $status: $text")
        JSONObject(text)
    } finally {
        connection.disconnect()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReforgeApp() {
    var baseUrl by remember { mutableStateOf("http://192.168.1.10:8765") }
    var token by remember { mutableStateOf("") }
    var connected by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("Connect to your Reforge desktop/server on the same trusted network.") }
    var roots by remember { mutableStateOf(listOf<String>()) }
    var currentPath by remember { mutableStateOf("") }
    var entries by remember { mutableStateOf(listOf<JSONObject>()) }
    var targetPath by remember { mutableStateOf("") }
    var targetKind by remember { mutableStateOf("folder") }
    var engines by remember { mutableStateOf(listOf<JSONObject>()) }
    var selectedEngines by remember { mutableStateOf(setOf<String>()) }
    var report by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun browse(path: String) {
        scope.launch {
            try {
                val result = apiCall(baseUrl, token, "GET",
                    "/v1/browse?path=" + URLEncoder.encode(path, "UTF-8"))
                currentPath = result.optString("path", path)
                val array = result.optJSONArray("entries") ?: JSONArray()
                entries = (0 until array.length()).map { array.getJSONObject(it) }
                message = "Browsing $currentPath"
            } catch (e: Exception) {
                message = e.message ?: "Browse failed"
            }
        }
    }

    MaterialTheme(colorScheme = darkColorScheme()) {
        Scaffold(topBar = {
            TopAppBar(title = { Text("REFORGE  /  Companion") })
        }) { padding ->
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedTextField(baseUrl, { baseUrl = it }, label = { Text("Desktop server URL") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(token, { token = it }, label = { Text("Bearer token") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = !busy && token.isNotBlank(), onClick = {
                        scope.launch {
                            busy = true
                            try {
                                apiCall(baseUrl, token, "GET", "/v1/health")
                                val rootResult = apiCall(baseUrl, token, "GET", "/v1/roots")
                                val rootArray = rootResult.optJSONArray("roots") ?: JSONArray()
                                roots = (0 until rootArray.length()).map { rootArray.getString(it) }
                                val engineResult = apiCall(baseUrl, token, "GET", "/v1/engines")
                                val engineArray = engineResult.optJSONArray("engines") ?: JSONArray()
                                engines = (0 until engineArray.length()).map { engineArray.getJSONObject(it) }
                                connected = true
                                message = "Connected. Select a project from an allowed folder."
                                roots.firstOrNull()?.let { browse(it) }
                            } catch (e: Exception) {
                                connected = false
                                message = e.message ?: "Connection failed"
                            } finally { busy = false }
                        }
                    }) { Text("Connect") }
                    if (busy) CircularProgressIndicator(modifier = Modifier.size(28.dp))
                }
                Text(message, style = MaterialTheme.typography.bodySmall)
                if (connected) {
                    Text("Allowed folders", style = MaterialTheme.typography.titleSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        roots.forEach { root ->
                            TextButton(onClick = { browse(root) }) { Text(root.substringAfterLast('/').ifBlank { root }) }
                        }
                    }
                    Text(currentPath, style = MaterialTheme.typography.labelSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = {
                            targetPath = currentPath
                            targetKind = "folder"
                        }) { Text("Select this folder") }
                    }
                    LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        items(entries, key = { it.optString("path") }) { item ->
                            val name = item.optString("name")
                            val path = item.optString("path")
                            val isFolder = item.optString("kind") == "folder"
                            Card(onClick = {
                                if (isFolder) browse(path) else {
                                    targetPath = path
                                    targetKind = "file"
                                }
                            }, modifier = Modifier.fillMaxWidth()) {
                                Row(Modifier.padding(12.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text((if (isFolder) "📁 " else "📄 ") + name)
                                    Text(if (isFolder) "Open" else "Select", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                    Text("Target: $targetPath ($targetKind)", style = MaterialTheme.typography.bodySmall)
                    Text("Engines", style = MaterialTheme.typography.titleSmall)
                    engines.forEach { engine ->
                        val name = engine.optString("name")
                        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                            Checkbox(checked = selectedEngines.contains(name), onCheckedChange = { checked ->
                                selectedEngines = if (checked) selectedEngines + name else selectedEngines - name
                            })
                            Column {
                                Text(name, style = MaterialTheme.typography.bodyMedium)
                                Text(engine.optString("description"), style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                    Button(enabled = !busy && targetPath.isNotBlank(), onClick = {
                        scope.launch {
                            busy = true
                            report = ""
                            try {
                                val payload = JSONObject()
                                    .put("target", targetPath)
                                    .put("kind", targetKind)
                                    .put("engines", JSONArray(selectedEngines.toList()))
                                val created = apiCall(baseUrl, token, "POST", "/v1/jobs", payload)
                                val id = created.getString("job_id")
                                message = "Analysis job $id"
                                while (true) {
                                    delay(1200)
                                    val state = apiCall(baseUrl, token, "GET", "/v1/jobs/$id")
                                    val status = state.optString("status")
                                    message = "Analysis: $status"
                                    if (status in listOf("succeeded", "partial", "failed")) {
                                        report = state.toString(2)
                                        break
                                    }
                                }
                            } catch (e: Exception) {
                                message = e.message ?: "Analysis request failed"
                            } finally { busy = false }
                        }
                    }) { Text("Run analysis") }
                    if (report.isNotBlank()) {
                        Text("Latest result", style = MaterialTheme.typography.titleSmall)
                        Text(report, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
