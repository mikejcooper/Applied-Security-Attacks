# get traces correlation chunks version with parallelization
def getMxCorrelationChunksPar( Hitracesij1j2 ) :
  ( Hi, Ti, i, j1, j2 ) = Hitracesij1j2
  tmp = corrcoef( Ti[:, j1:j2 ].T, Hi[:, i     ].T )[chunkSize][:chunkSize]
  return ( i, j1, j2, tmp )
# controller for chunks correlation


def corParChunk( Hi, traces, pool ) :
  ( r , Hc ) = Hi.shape
  ( r , Tc ) = traces.shape
  R = zeros( (Hc, Tc) )
  chunks = Tc / chunkSize
  inputs = []
  for i in range ( first, last ) :
    for j in range( chunks ) :
      j1 = j * chunkSize
      j2 = (j + 1) * chunkSize
      inputs.append( (Hi, traces, i, j1, j2) )
  for data in pool.map(getMxCorrelationChunksPar,inputs):
    ( i, j1, j2, cor) = data
    R[i, j1:j2] = cor
  return R