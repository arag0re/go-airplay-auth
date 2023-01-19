package tlv8

func Decode(data []byte) []TLV8Item {
	var items []TLV8Item
	offset := 0
	dataLength := len(data)
	previousType := byte(0xff)
	previousSize := uint16(0)
	for offset < dataLength {
		type1 := data[offset]
		offset++
		size := data[offset]
		offset++
		itemData := data[offset : offset+int(size)]
		if type1 == previousType && previousSize == 255 {
			index := len(items) - 1
			oldItem := items[index]
			oldData := oldItem.Value
			newData := append(oldData, itemData...)
			oldItem.Value = newData
		} else {
			newItem := TLV8Item{Tag: TLV8Tag(uint8(type1)), Value: itemData}
			items = append(items, newItem)
		}
		offset += int(size)
		previousType = type1
		previousSize = uint16(size)
	}

	return items
}

func Encode(items []TLV8Item, stream *[]byte) int {
	offset := 0
	dataOffset := 0
	previousType := byte(0xff)
	remainingBytes := 0
	for i := 0; i < len(items); i++ {
		item := items[i]
		typeUint := uint8(item.Tag)
		data := item.Value
		size := len(data)
		previousType = typeUint
		remainingBytes = size
		dataOffset = 0
		for remainingBytes > 0 {
			dataSize := 255
			if remainingBytes < 255 {
				dataSize = remainingBytes
			}
			if i == 0 {
				*stream = make([]byte, dataSize+2)
			} else {
				*stream = append(*stream, make([]byte, dataSize+2)...)
			}
			(*stream)[offset] = typeUint
			(*stream)[offset+1] = byte(dataSize)
			copy((*stream)[offset+2:], data[dataOffset:dataOffset+dataSize])
			offset += dataSize + 2
			remainingBytes -= dataSize
			dataOffset += dataSize
		}
	}
	print(previousType)
	return offset
}

//func (tlv []TLV8Item) ItemWithTag(tag TLV8Tag) *TLV8Item {
//    for _, item := range tlv {
//        if item.Tag == tag {
//            return &item
//        }
//    }
//    return nil
//}
