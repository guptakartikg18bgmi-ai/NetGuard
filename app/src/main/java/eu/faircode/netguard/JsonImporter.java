package eu.faircode.netguard;

/*
    This file is part of NetGuard (Modified).
    License: GPL-3.0
*/

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

import androidx.preference.PreferenceManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.util.Scanner;

public class JsonImporter {

    private static final String TAG = "NG.JsonImporter";

    /**
     * Import firewall rules from JSON stream.
     *
     * Expected JSON format (array of objects):
     * [
     *   {
     *     "appName": "YouTube",
     *     "pkg1Name": "com.google.android.youtube",
     *     "port": -1,
     *     "proto": "tcp",
     *     "server": "*",
     *     "serverStrType": "ip4",
     *     "mobile": "allow",
     *     "wifi": "allow",
     *     "isCustom": false,
     *     "priority": 0
     *   }
     * ]
     *
     * @return number of rules applied, or -1 on error
     */
    public static int importRules(Context context, InputStream is) {
        int applied = 0;
        try {
            String raw = new Scanner(is, "UTF-8").useDelimiter("\\A").next();
            JSONArray arr = new JSONArray(raw);

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            DatabaseHelper db = DatabaseHelper.getInstance(context);

            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);

                String pkg    = obj.optString("pkg1Name", null);
                String mobile = obj.optString("mobile", "allow");
                String wifi   = obj.optString("wifi", "allow");

                if (pkg == null || pkg.trim().isEmpty()) {
                    Log.w(TAG, "Skipping entry " + i + ": missing pkg1Name");
                    continue;
                }

                // NetGuard convention: true = allowed, false = blocked
                boolean wifiAllowed   = !"block".equalsIgnoreCase(wifi.trim());
                boolean mobileAllowed = !"block".equalsIgnoreCase(mobile.trim());

                try {
                    applyRule(db, pkg, wifiAllowed, mobileAllowed);
                    Log.i(TAG, "Rule applied: " + pkg
                            + " wifi=" + (wifiAllowed ? "allow" : "block")
                            + " mobile=" + (mobileAllowed ? "allow" : "block"));
                    applied++;
                } catch (Exception e) {
                    Log.e(TAG, "Failed to apply rule for " + pkg, e);
                }
            }

            // Reload VPN rules so changes take effect immediately
            SinkholeService.reload("json_import", context, false);
            Log.i(TAG, "Import complete. Rules applied: " + applied + "/" + arr.length());

        } catch (Exception e) {
            Log.e(TAG, "JSON import failed", e);
            return -1;
        }
        return applied;
    }

    /**
     * Write allow/block rule into NetGuard's 'app' table.
     * Uses SharedPreferences which is NetGuard's primary rule store per-app.
     */
    private static void applyRule(DatabaseHelper db,
                                  String packageName,
                                  boolean wifiAllowed,
                                  boolean mobileAllowed) {
        // NetGuard stores per-app rules in SharedPreferences
        // Keys: "wifi:<pkg>" and "other:<pkg>"  (other = mobile/cellular)
        // true = allow through, false = block
        // These are read in Rule.java getRules() → ServiceSinkhole
        SharedPreferences.Editor ed = db.getContext()
                .getSharedPreferences("netguard3", Context.MODE_PRIVATE)
                .edit();
        // NetGuard uses these pref keys for app-level overrides
        ed.putBoolean("wifi:" + packageName, wifiAllowed);
        ed.putBoolean("other:" + packageName, mobileAllowed);
        ed.apply();
    }
}
