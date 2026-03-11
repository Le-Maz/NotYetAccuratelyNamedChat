package me.lmazur.notyetaccuratelynamedchat

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.compose_app.Vault
import uniffi.compose_app.Database

/**
 * State manager for the Vault.
 */
object VaultManager {
    var activeVault by mutableStateOf<Vault?>(null)
        private set

    // Simple flag to determine if we are setting up for the first time
    // In a real app, you'd check database.hasMetadata()
    var isVaultInitialized by mutableStateOf(false)

    fun unlock(vault: Vault) {
        activeVault = vault
    }

    fun lock() {
        activeVault = null
    }
}

@Composable
fun App(database: Database) {
    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            val currentVault = VaultManager.activeVault

            if (currentVault == null) {
                UnlockVaultScreen(
                    database = database,
                    isCreationMode = !VaultManager.isVaultInitialized,
                    onVaultUnlocked = {
                        VaultManager.isVaultInitialized = true
                        VaultManager.unlock(it)
                    }
                )
            } else {
                AuthenticatedVaultScreen(
                    onLockRequested = { VaultManager.lock() }
                )
            }
        }
    }
}

/**
 * Screen displayed when the vault is locked or needs to be created.
 */
@Composable
fun UnlockVaultScreen(
    database: Database,
    isCreationMode: Boolean,
    onVaultUnlocked: (Vault) -> Unit
) {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .safeContentPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (isCreationMode) "Create Vault" else "Unlock Vault",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(16.dp))

        PasswordTextField(
            value = password,
            onValueChange = { password = it },
            enabled = !isLoading,
            isError = errorMessage != null
        )

        if (errorMessage != null) {
            Text(
                text = errorMessage!!,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp)
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading && password.isNotEmpty(),
            onClick = {
                scope.launch {
                    isLoading = true
                    errorMessage = null
                    try {
                        val vault = if (isCreationMode) {
                            // Directly use the static constructor
                            Vault.create(database, "default_vault", password)
                        } else {
                            // Directly use the static loader
                            Vault.load(database, "default_vault", password)
                        }

                        onVaultUnlocked(vault)
                        password = ""
                    } catch (e: Exception) {
                        errorMessage = "Invalid password or encryption error"
                    } finally {
                        isLoading = false
                    }
                }
            }
        ) {
            if (isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
            } else {
                Text(if (isCreationMode) "Create" else "Enter")
            }
        }
    }
}

/**
 * Screen displayed once the vault is successfully unlocked.
 */
@Composable
fun AuthenticatedVaultScreen(onLockRequested: () -> Unit) {
    Column(
        modifier = Modifier
            .safeContentPadding()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Vault Unlocked", style = MaterialTheme.typography.headlineSmall)

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth().weight(1f, fill = false),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Box(Modifier.padding(16.dp).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Text("Your secure content goes here", style = MaterialTheme.typography.bodyMedium)
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onLockRequested,
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.secondary
            )
        ) {
            Text("Lock Vault")
        }
    }
}

@Composable
fun PasswordTextField(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean,
    isError: Boolean
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text("Password") },
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
        isError = isError,
        singleLine = true
    )
}
