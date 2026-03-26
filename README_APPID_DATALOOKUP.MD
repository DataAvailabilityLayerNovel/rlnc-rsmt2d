# Avail AppID Data Lookup Guide

Tai lieu nay tong hop noi dung tu doan chat ve:

- Cach Avail sap xep du lieu theo AppID
- Cach header luu bo chi muc DataLookup

## 1. Thanh phan chinh

### AppId

`AppId` la ID cua ung dung, la wrapper quanh `u32`.

```rust
pub struct AppId(pub u32);
```

### AppExtrinsic

`AppExtrinsic` gom 2 phan:

- `app_id`: ung dung so huu payload
- `data`: payload da encode

```rust
pub struct AppExtrinsic {
    pub app_id: AppId,
    pub data: Vec<u8>,
}
```

### DataLookup

`DataLookup` la bo chi muc map tu `AppId` sang khoang vi tri du lieu (`Range<u32>`).

```rust
pub struct DataLookup {
    pub(crate) index: Vec<(AppId, Range<u32>)>,
}
```

Y nghia:

- Moi `AppId` duoc gan mot khoang lien tiep trong flat data
- Co the truy van nhanh bang `range_of(app_id)`

## 2. Cach Avail sap xep du lieu theo AppID

Trong qua trinh flatten block:

1. Extrinsics duoc sort theo `app_id`
2. Extrinsics co cung `app_id` duoc group lien tiep
3. Tinh do dai du lieu tung app
4. Dung offset cong don de tao `Range` cho moi app trong `DataLookup`

Vi du logic:

- App 1: 0..100
- App 2: 100..250
- App 5: 250..500

## 3. Header luu bo chi muc nhu the nao

```rust
// Trong header/mod.rs
pub struct Header<N, H> {
    pub parent_hash: H::Output,
    pub number: N,
    pub state_root: H::Output,
    pub extrinsics_root: H::Output,
    pub digest: Digest,
    pub extension: HeaderExtension,  // ← Chứa app_lookup
}
```

`Header` chua `HeaderExtension`, va trong extension co:

- `app_lookup: DataLookup`
- `commitment: KateCommitment`

```rust
pub struct HeaderExtension {
    pub app_lookup: DataLookup,      // ← Bộ chỉ mục
    pub commitment: KateCommitment,  // ← Cam kết KZG
}
```

## 4. Dang luu tren chain: CompactDataLookup

Khi encode vao header, `DataLookup` khong luu nguyen ban ma chuyen sang dang nen `CompactDataLookup`:

```rust
pub struct CompactDataLookup {
    pub(crate) size: u32,
    pub(crate) index: Vec<DataLookupItem>,
}

pub struct DataLookupItem {
    pub app_id: AppId,
    pub start: u32,
}
```

### Cach nen

- Chi luu `start` cua moi app, khong luu `end`
- `end` cua app hien tai = `start` cua app ke tiep
- `end` cua app cuoi = `size`
- AppId(0) duoc bo qua trong compact index (tru error marker)

Vi du:
DataLookup day du:

- (AppId(1), 0..100)
- (AppId(2), 100..250)
- (AppId(5), 250..500)

CompactDataLookup:

- size = 500
- index = [(1,0), (2,100), (5,250)]

## 5. Decode tu header ve DataLookup day du

Khi decode:

1. Doc `CompactDataLookup`
2. Tai tao tung range bang cap `start` lien tiep
3. Range cuoi cung dung `size`
4. Validate consistency (`lookup.len() == compacted.size`)

Neu compact data o trang thai loi (`size == 0` va `index` khong rong, hoac `size == u32::MAX`) thi convert ve `DataLookup::new_error()`.

## 6. Truy xuat du lieu theo AppID

Sau khi co `DataLookup`, co 2 ham chinh:

- `range_of(app_id)`: lay range logic theo chunk index
- `projected_range_of(app_id, chunk_size)`: doi sang byte range theo chunk size

Dieu nay duoc dung trong recovery de:

- Lay row/cell lien quan den mot app
- Reconstruct rieng data cua app do

## 7. Tom tat ngan

- Du lieu duoc sap xep tang dan theo AppID
- Moi app chiem mot khoang lien tiep trong flat data
- Header luu bo chi muc o dang compact de giam kich thuoc
- Khi can, node decode va tai tao lai full range de proof/recovery
