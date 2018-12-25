Change ID b9b5320f04b9c1fcbe9e8ebf838e4a2f74f6b0c3 Tue Dec 25 10:00:30 2018
From: Manish4586 <manish.n.manish45@gmail.com>
Date: Tue, 25 Tue 2018 20:33:09 +0300
Subject: Keymaster 4.0
--- system/core/init/builtins.cpp
+++ system/core/init/builtins.cpp
@@ -1020,6 +1020,16 @@
         {{"exec", "/system/bin/vdc", "--wait", "cryptfs", "enablefilecrypto"}, args.context});
 }
 
+static Result<Success> do_install_keyring(const BuiltinArguments& args) {
+    if (e4crypt_install_keyring()) {
+        LOG(ERROR) << "failed to install keyring";
+        return Error() << "e4crypt_install_keyring() failed";
+    }
+    property_set("ro.crypto.state", "encrypted");
+    property_set("ro.crypto.type", "file");
+    return Success();
+}
+
 static Result<Success> do_init_user0(const BuiltinArguments& args) {
     return ExecWithRebootOnFailure(
         "init_user0_failed",
@@ -1050,6 +1060,7 @@
         {"init_user0",              {0,     0,    {false,  do_init_user0}}},
         {"insmod",                  {1,     kMax, {true,   do_insmod}}},
         {"installkey",              {1,     1,    {false,  do_installkey}}},
+        {"install_keyring",         {0,     0,    {false,  do_install_keyring}}},
         {"load_persist_props",      {0,     0,    {false,  do_load_persist_props}}},
         {"load_system_props",       {0,     0,    {false,  do_load_system_props}}},
         {"loglevel",                {1,     1,    {false,  do_loglevel}}},
		 
--- hardware/interfaces/keymaster/4.0/support/Keymaster.cpp
+++ hardware/interfaces/keymaster/4.0/support/Keymaster.cpp
@@ -111,11 +111,10 @@
     CHECK(serviceManager) << "Could not retrieve ServiceManager";
 
     auto km4s = enumerateDevices<Keymaster4>(serviceManager);
-    auto km3s = enumerateDevices<Keymaster3>(serviceManager);
 
     auto result = std::move(km4s);
-    result.insert(result.end(), std::make_move_iterator(km3s.begin()),
-                  std::make_move_iterator(km3s.end()));
+    result.insert(result.end(), std::make_move_iterator(km4s.begin()),
+                  std::make_move_iterator(km4s.end()));
 
     std::sort(result.begin(), result.end(),
               [](auto& a, auto& b) { return a->halVersion() > b->halVersion(); });
			   
--- bootable/recovery/crypto/ext4crypt/Decrypt.cpp
+++ bootable/recovery/crypto/ext4crypt/Decrypt.cpp
@@ -1319,11 +1319,11 @@
     ret = gk_device->verify(gk_device, user_id, 0, (const uint8_t *)handle.c_str(), st.st_size,
                 (const uint8_t *)Password.c_str(), (uint32_t)Password.size(), &auth_token, &auth_token_len,
                 &should_reenroll);
+#endif
     if (ret !=0) {
-		printf("failed to verify\n");
+		printf("failed to verify, ret=%d\n", ret);
 		return false;
 	}
-#endif
 	char token_hex[(auth_token_len*2)+1];
 	token_hex[(auth_token_len*2)] = 0;
 	uint32_t i;
@@ -1336,7 +1336,7 @@
 		printf("e4crypt_unlock_user_key returned fail\n");
 		return false;
 	}
-	if (!e4crypt_prepare_user_storage(nullptr, user_id, 0, flags)) {
+	if (!e4crypt_prepare_user_storage("", user_id, 0, flags)) {
 		printf("failed to e4crypt_prepare_user_storage\n");
 		return false;
 	}

	
+++ b/minuitwrp/graphics_fbdev.cpp
@@ -288,7 +288,7 @@ static GRSurface* fbdev_flip(minui_backend* backend __unused) {
     unsigned int idx;
     unsigned char tmp;
     unsigned char* ucfb_vaddr = (unsigned char*)gr_draw->data;
-    for (idx = 0 ; idx < (gr_draw->height * gr_draw->row_bytes);
+    for (idx = 0 ; idx < (unsigned int)(gr_draw->height * gr_draw->row_bytes);
             idx += 4) {
         tmp = ucfb_vaddr[idx];
         ucfb_vaddr[idx    ] = ucfb_vaddr[idx + 2];