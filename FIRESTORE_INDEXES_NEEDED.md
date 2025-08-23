# 🔥 Firestore Indexes Required for Full Functionality

## Overview
The stuck audit prevention system has been temporarily simplified to avoid Firestore index requirements. To restore full functionality, you need to create the following composite indexes.

## 📍 Where to Create Indexes
**Firebase Console**: https://console.firebase.google.com/project/vibelog-lj17r/firestore/indexes

## 🗂️ Required Indexes

### 1. **Active Audit Detection Index**
- **Collection**: `security_audits`
- **Fields**:
  - `status` (Ascending)
  - `userId` (Ascending) 
  - `__name__` (Ascending)
- **Purpose**: Enables `hasActiveAudit()` and `getActiveAudit()` methods
- **Query**: `where('status', '==', 'running') + where('userId', '==', userId)`

### 2. **Audit History Index**
- **Collection**: `security_audits`
- **Fields**:
  - `status` (Ascending)
  - `userId` (Ascending)
  - `completedAt` (Descending)
  - `__name__` (Ascending)
- **Purpose**: Enables `getAuditHistory()` method with proper sorting
- **Query**: `where('status', '==', 'completed') + where('userId', '==', userId) + orderBy('completedAt', 'desc')`

### 3. **Stuck Audit Prevention Index (Worker)**
- **Collection**: `security_audits`
- **Fields**:
  - `progress.is_running` (Ascending)
  - `progress.last_updated` (Ascending)
  - `__name__` (Ascending)
- **Purpose**: Enables worker heartbeat cleanup system
- **Query**: `where('progress.is_running', '==', True) + where('progress.last_updated', '<', cutoff_time)`

## 🚀 How to Create Indexes

### Option 1: Direct Link (Recommended)
Click this link to create the first index:
```
https://console.firebase.google.com/v1/r/project/vibelog-lj17r/firestore/indexes?create_composite=ClVwcm9qZWN0cy92aWJlbG9nLWxqMTdyL2RhdGFiYXNlcy8oZGVmYXVsdCkvY29sbGVjdGlvbkdyb3Vwcy9zZWN1cml0eV9hdWRpdHMvaW5kZXhlcy9fEAEaFwoTcHJvZ3Jlc3MuaXNfcnVubmluZxABGhkKFXByb2dyZXNzLmxhc3RfdXBkYXRlZBABGgwKCF9fbmFtZV9fEAE
```

### Option 2: Manual Creation
1. Go to Firebase Console → Firestore → Indexes
2. Click "Create Index"
3. Set Collection ID to `security_audits`
4. Add fields in the order specified above
5. Click "Create"

## ⏱️ Index Creation Time
- **Small collections**: 1-5 minutes
- **Large collections**: 10-30 minutes
- **Very large collections**: 1-2 hours

## 🔄 After Indexes Are Created

### 1. **Re-enable Worker Functions**
In `worker/main.py`, restore the full stuck audit prevention:

```python
def _heartbeat_cleanup(self):
    """Periodic cleanup of stuck audits"""
    try:
        if not FIREBASE_AVAILABLE:
            return
            
        # Find audits that haven't updated in a while
        cutoff_time = datetime.now() - timedelta(seconds=self.heartbeat_timeout)
        cutoff_str = cutoff_time.isoformat()
        
        audits_ref = self.db.collection('security_audits')
        stuck_audits = audits_ref.where('progress.last_updated', '<', cutoff_str).where('progress.is_running', '==', True).stream()
        
        # ... rest of the cleanup logic
```

### 2. **Re-enable Frontend Functions**
In `src/lib/firebase-audit-service.ts`, restore the full queries:

```typescript
static async hasActiveAudit(userId: string): Promise<boolean> {
  try {
    // Query for pending audits
    const pendingQuery = query(
      collection(db, this.COLLECTION_NAME),
      where('status', '==', 'pending'),
      where('userId', '==', userId)
    );
    
    // Query for running audits
    const runningQuery = query(
      collection(db, this.COLLECTION_NAME),
      where('status', '==', 'running'),
      where('userId', '==', userId)
    );
    
    // ... rest of the logic
  }
}
```

## 🎯 Current Status
- ✅ **Worker**: Simplified, no more 400 errors
- ✅ **Frontend**: Simplified, no more connection issues
- ✅ **Audits**: Should work normally now
- ⏳ **Full Prevention**: Waiting for indexes

## 🚨 Important Notes
- **Indexes are required** for production use
- **Without indexes**, complex queries will fail with 400 errors
- **Simple queries** (single field) work without indexes
- **Composite queries** (multiple fields + ordering) require indexes

## 📞 Support
If you need help creating indexes or have questions:
1. Check Firebase Console for index creation status
2. Monitor worker logs for any remaining errors
3. Test audit functionality after indexes are created
