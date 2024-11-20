package com.credman.cmwallet.ui

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Face
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.credman.cmwallet.data.model.Credential
import com.credman.cmwallet.data.model.CredentialItem
import com.credman.cmwallet.data.model.MdocCredential

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: HomeViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val openCredentialDialog = remember { mutableStateOf<CredentialItem?>(null) }
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            CenterAlignedTopAppBar(
                title = {
                    Text(text = "CMWallet")
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier.padding(innerPadding),
        ) {
            CredentialList(
                uiState.credentials,
                onCredentialClick = { cred ->
                    openCredentialDialog.value=cred
                }
            )
        }
    }
    if(openCredentialDialog.value != null) {
        CredentialDialog(
            onDismissRequest = {
                openCredentialDialog.value = null
            },
            credentialItem = openCredentialDialog.value!!
        )
    }
}

@Composable
fun CredentialList(
    credentials: List<CredentialItem>,
    onCredentialClick: (CredentialItem) -> Unit
) {
    Column(
        Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        LazyColumn(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(15.dp)
        ) {
            credentials.forEach {
                item {
                    CredentialCard(cred = it, onCredentialClick)
                }
            }
        }
    }
}

@Composable
fun CredentialDialog(
    onDismissRequest: () -> Unit,
    credentialItem: CredentialItem
) {
    Dialog(onDismissRequest = { onDismissRequest() }) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(400.dp)
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column {
                Text(
                    text = "${credentialItem.metadata.title}",
                    modifier = Modifier.fillMaxWidth().padding(10.dp),
                    textAlign = TextAlign.Center,
                )
                if (credentialItem.credential is MdocCredential) {
                    credentialItem.credential.nameSpaces.forEach { (namespace, mdocNameSpace) ->
                        Column(modifier = Modifier.fillMaxWidth().padding(10.dp).verticalScroll(rememberScrollState())) {
                            Row(Modifier.background(Color.LightGray)) {
                                Text(
                                    text=namespace,
                                    modifier = Modifier.border(1.dp, Color.Black).weight(1.0f).padding(5.dp)
                                )
                            }
                            mdocNameSpace.data.forEach { (fieldName, mdocField) ->
                                Row() {
                                    Text(
                                        text=fieldName,
                                        modifier = Modifier.border(1.dp, Color.Black).weight(0.5f).padding(5.dp)
                                    )
                                    Text(
                                        text=mdocField.value.toString(),
                                        modifier = Modifier.border(1.dp, Color.Black).weight(0.5f).padding(5.dp),
                                        softWrap = false
                                    )
                                }
                            }
                        }
                    }

                }

            }

        }
    }
}

@Composable
fun CredentialCard(
    cred: CredentialItem,
    onCredentialClick: (CredentialItem) -> Unit
) {
    val metadata = cred.metadata
    val cardArt = Base64.decode(metadata.icon, 0)
    Card(
        modifier = Modifier.size(350.dp, 210.dp),
        shape = CardDefaults.shape,
        onClick = {
            onCredentialClick(cred)
        }
    ) {
        if (cardArt.size > 0) {
            Image(
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
                bitmap = BitmapFactory.decodeByteArray(cardArt, /*offset=*/0, cardArt.size)!!
                    .asImageBitmap(),
                contentDescription = null
            )
        } else {
            Box(
                Modifier
                    .fillMaxSize()
                    .background(
                        brush = Brush.horizontalGradient(
                            colors = listOf(
                                Color(0x407D5280), Color(0x40EFB8C8)
                            )
                        )
                    )
            ) {
                Row() {
                    Image(
                        modifier = Modifier
                            .padding(10.dp)
                            .size(80.dp, 80.dp),
                        imageVector = Icons.Filled.Face,
                        contentDescription = ""
                    )
                    Column(
                        modifier = Modifier.padding(10.dp, 20.dp)
                    ) {
                        Text(
                            text = metadata.title,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = metadata.subtitle ?: "",
                            fontSize = 16.sp,
                        )
                    }
                }
            }
        }

    }

}